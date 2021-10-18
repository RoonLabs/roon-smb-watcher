/* Netbios Discover */
/* originally copied from libdsm example code */
#include <stdio.h>
#ifdef PLATFORM_WINDOWS
#include <windows.h>
#include <lm.h>

#ifndef UNICODE
#define UNICODE
#endif

#else
#include <inttypes.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "smb2/smb2.h"
#include "smb2/libsmb2.h"
#include "smb2/libsmb2-raw.h"
#endif

#include <arpa/inet.h>

#include "bdsm.h"

struct credentials {
    char *workgroup;
    char *username;
    char *password;
};

static void print_entry(const char *what, void *p_opaque,
                        netbios_ns_entry *entry) {
    struct in_addr addr;

    addr.s_addr = netbios_ns_entry_ip(entry);

    printf("%s(%p): Ip: %s, name: %s/%s<%x>\n",
           what,
           p_opaque,
           inet_ntoa(addr),    netbios_ns_entry_group(entry),
           netbios_ns_entry_name(entry),
           netbios_ns_entry_type(entry));
}

#ifdef PLATFORM_WINDOWS
static int list_shares_win(void *p_opaque,
                       netbios_ns_entry *entry) {
    PSHARE_INFO_502 BufPtr,p;
    NET_API_STATUS res;
    LMSTR lpszServer = NULL;
    DWORD er=0,tr=0,resume=0, i;

    const char* cstrName = netbios_ns_entry_name(entry);
    int name_len = strlen(cstrName);
    lpszServer = calloc(name_len + 1, sizeof(TCHAR));
    for (int i = 0; i < name_len; i++) {
        lpszServer[i] = cstrName[i];
    }
    
    do {
        res = NetShareEnum (lpszServer, 502, (LPBYTE *) &BufPtr, MAX_PREFERRED_LENGTH, &er, &tr, &resume);
        if(res == ERROR_SUCCESS || res == ERROR_MORE_DATA) {
            p=BufPtr;
            printf("        share count: %i\n", er);
            for(i=1;i<=er;i++) {
                printf("        share name: %S\n", p->shi502_netname);
                p++;
            }
            NetApiBufferFree(BufPtr);
        }
        else 
            printf("Error: %ld\n",res);
    }
    while (res==ERROR_MORE_DATA);
}
#else
static int list_shares_smb1(void *p_opaque,
                            netbios_ns_entry *entry) {
    struct credentials *creds = (struct credentials *)p_opaque;
    struct in_addr  addr;
    smb_session   *session;
    smb_tid     tid;
    smb_fd      fd;

    session = smb_session_new();
    if (session == NULL)
        return 1;

    addr.s_addr = netbios_ns_entry_ip(entry);

    int session_ret = smb_session_connect(session, netbios_ns_entry_name(entry), 
                                        addr.s_addr, SMB_TRANSPORT_TCP);
    if (session_ret) {
        printf("    Unable to connect to host %s\n", inet_ntoa(addr));
        return session_ret;
    }

    smb_session_set_creds(session, creds->workgroup, creds->username, creds->password);
    int login_ret = smb_session_login(session);
    if (login_ret == DSM_SUCCESS) {
        if (smb_session_is_guest(session))
            printf("    Logged in as GUEST\n");
        else
            printf("    Successfully logged in\n");
    }
    else {
        printf("    Auth failed %s\n", inet_ntoa(addr));
        return login_ret;
    }

    smb_share_list list;
    size_t count;
    int list_ret = smb_share_get_list(session, &list, &count);
    if (list_ret == DSM_SUCCESS) {
        printf("        share count: %i\n", count);
    }
    else {
        printf("    Unable to connect to share, ret value: %i\n", list_ret);
        if (list_ret == DSM_ERROR_NT) {
            uint32_t nt_status = smb_session_get_nt_status(session);
            printf("    nt_status: %x\n", nt_status);
        }
      
        return list_ret;
    }

    for (int i = 0; i < count; i++) {
        printf("        share name: %s\n", smb_share_list_at(list, i));
    }
  
    smb_share_list_destroy(list);
    smb_session_destroy(session);

    return 0;
}

int cb_status;

void se_cb(struct smb2_context *smb2, int status,
                void *command_data, void *private_data) {
        struct srvsvc_netshareenumall_rep *rep = command_data;
        int i;

        if (status) {
                printf("    failed to enumerate shares [%d](%s) %s\n",
                       status, strerror(-status), smb2_get_error(smb2));
                cb_status = status;
                return;
        }

        printf("        share count: %i\n", rep->ctr->ctr1.count);
        for (i = 0; i < rep->ctr->ctr1.count; i++) {
                printf("        share name: %-20s %-20s", rep->ctr->ctr1.array[i].name,
                       rep->ctr->ctr1.array[i].comment);
                if ((rep->ctr->ctr1.array[i].type & 3) == SHARE_TYPE_DISKTREE) {
                        printf("     DISKTREE");
                }
                if ((rep->ctr->ctr1.array[i].type & 3) == SHARE_TYPE_PRINTQ) {
                        printf("     PRINTQ");
                }
                if ((rep->ctr->ctr1.array[i].type & 3) == SHARE_TYPE_DEVICE) {
                        printf("     DEVICE");
                }
                if ((rep->ctr->ctr1.array[i].type & 3) == SHARE_TYPE_IPC) {
                        printf("     IPC");
                }
                if (rep->ctr->ctr1.array[i].type & SHARE_TYPE_TEMPORARY) {
                        printf("     TEMPORARY");
                }
                if (rep->ctr->ctr1.array[i].type & SHARE_TYPE_HIDDEN) {
                        printf("     HIDDEN");
                }
                printf("    \n");
        }

        smb2_free_data(smb2, rep);

        cb_status = 0;
}

static int list_shares_smb2(void *p_opaque,
                            netbios_ns_entry *entry) {
    struct credentials *creds = (struct credentials *)p_opaque;
    struct smb2_context *smb2;
    struct smb2_url *url;
    struct pollfd pfd;

    smb2 = smb2_init_context();
    if (smb2 == NULL) {
        printf("    Failed to init context\n");
        return 1;
    }

    cb_status = 1;

    struct in_addr addr;
    addr.s_addr = netbios_ns_entry_ip(entry);
    char *server = inet_ntoa(addr);
    smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);

    if (creds->username[0] != '\0') smb2_set_user(smb2, creds->username);
    if (creds->password[0] != '\0') smb2_set_password(smb2, creds->password);

    int connect_ret = smb2_connect_share(smb2, server, "IPC$", NULL);
    if (connect_ret < 0) {
        printf("    Failed to connect to IPC$. %s\n",
               smb2_get_error(smb2));
        return -connect_ret;
    }

    int enum_ret = smb2_share_enum_async(smb2, se_cb, NULL);
    if (enum_ret != 0) {
        printf("    smb2_share_enum failed. %s\n", smb2_get_error(smb2));
        return -enum_ret;
    }

    while (cb_status > 0) {
        pfd.fd = smb2_get_fd(smb2);
        pfd.events = smb2_which_events(smb2);

        int poll_ret = poll(&pfd, 1, 1000);
        if (poll_ret < 0) {
            printf("    Poll failed");
            return errno;
        }
        if (pfd.revents == 0) {
            continue;
        }
        if (smb2_service(smb2, pfd.revents) < 0) {
            printf("    smb2_service failed with : %s\n",
                   smb2_get_error(smb2));
            break;
        }
    }

    smb2_disconnect_share(smb2);
    smb2_destroy_context(smb2);
        
    return -cb_status;
}
#endif
static int list_shares(void *p_opaque,
                       netbios_ns_entry *entry) {
    struct credentials *creds = (struct credentials *)p_opaque;
    struct credentials *guest_creds = malloc(sizeof(struct credentials));
    guest_creds->workgroup = "Guest";
    guest_creds->username  = "";
    guest_creds->password  = "";

#ifdef PLATFORM_WINDOWS
    printf("  attempting to list shares using netshareenum as guest\n");
    int win_ret = list_shares_win(guest_creds, entry);
    printf("  return value: %d\n", win_ret);
    if (win_ret == 0) {
        return 0;
    }

    if (creds->username[0] != '\0') {
    printf("  attempting to list shares using netshareenum with credentials\n");
        win_ret = list_shares_win(creds, entry);
        printf("  return value: %d\n", win_ret);
        if (win_ret == 0) {
            return 0;
        }
    }
#else
    printf("  attempting to list shares over smb1 as guest\n");
    int smb1_ret = list_shares_smb1(guest_creds, entry);
    printf("  return value: %d\n", smb1_ret);
    if (smb1_ret == 0) {
        return 0;
    }

    printf("  attempting to list shares over smb2 as guest\n");
    int smb2_ret = list_shares_smb2(guest_creds, entry);
    printf("  return value: %d\n", smb2_ret);
    if (smb2_ret == 0) {
        return 0;
    }

    if (creds->username[0] != '\0') {
        printf("  attempting to list shares over smb1 with credentials\n");
        smb1_ret = list_shares_smb1(creds, entry);
        printf("  return value: %d\n", smb1_ret);
        if (smb1_ret == 0) {
            return 0;
        }

        printf("  attempting to list shares over smb2 with credentials\n");
        smb2_ret = list_shares_smb2(creds, entry);
        printf("  return value: %d\n", smb2_ret);
        if (smb2_ret == 0) {
            return 0;
        }
    }
#endif
}


static void on_entry_added(void *p_opaque,
                           netbios_ns_entry *entry) {
    print_entry("added", p_opaque, entry);
    int list_ret = list_shares(p_opaque, entry);
}

static void on_entry_removed(void *p_opaque,
                             netbios_ns_entry *entry) {
    print_entry("removed", p_opaque, entry);
}

int main(int argc, char** argv) {
    struct credentials *args = malloc(sizeof(struct credentials));
    if (argc >= 4) {
        args->workgroup = argv[1];
        args->username  = argv[2];
        args->password  = argv[3];
    } else if (argc == 3) {
        args->workgroup = "";
        args->username  = argv[1];
        args->password  = argv[2];
    } else if (argc == 2) {
        args->workgroup = "";
        args->username  = argv[1];
        args->password  = "";
    } else if (argc == 1) {
        args->workgroup = "";
        args->username  = "";
        args->password  = "";
    }
  
    netbios_ns *ns;
    netbios_ns_discover_callbacks callbacks;

    ns = netbios_ns_new();

    callbacks.p_opaque = (void*)args;
    callbacks.pf_on_entry_added = on_entry_added;
    callbacks.pf_on_entry_removed = on_entry_removed;

    printf("Discovering...\nPress Enter to quit\n");
    int ret = netbios_ns_discover_start(ns,
                                        4, // broadcast every 4 sec
                                        &callbacks);
    printf("return code from start: %i\n", ret);
    if (ret != 0) {
        fprintf(stderr, "Error while discovering local network\n");
        exit(42);
    }

    getchar();

    netbios_ns_discover_stop(ns);

    return (0);
}
