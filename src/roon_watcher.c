#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef PLATFORM_WINDOWS
#include <winsock2.h>
#include <windows.h>

#else

#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#endif

#include "bdsm.h"
#ifndef PLATFORM_WINDOWS
#include "smb2/smb2.h"
#include "smb2/libsmb2.h"
#include "smb2/libsmb2-raw.h"
#endif

#include "roon_error.h"

enum watcher_mode {
    MODE_TEST,
    MODE_HOSTS,
    MODE_SHARES,
};

struct watcher_options {
    char *workgroup;
    char *username;
    char *password;
    enum watcher_mode mode;
};

typedef struct watcher_options watcher_options;

#ifdef PLATFORM_WINDOWS
/*
static int inet_aton(const char *cp, struct in_addr *inp) {
    unsigned long ip = in_addr(cp);
    if (ip == INADDR_NONE) {
        return -1;
    } else {
        inp->S_addr
    }
}
*/
#endif

static void print_if(bool print, const char *fmt, ...) {
    if (print) {
        va_list args;
        va_start(args, fmt);
        fprintf(stdout, fmt, args);
        va_end(args);
    }
}

static void print_entry(const char *what,
                        netbios_ns_entry *entry,
                        watcher_options *options) {
    struct in_addr addr;

    addr.s_addr = netbios_ns_entry_ip(entry);
    char *format = "%s: Ip: %s %s/%s<%x>\n";
    if (options->mode == MODE_HOSTS) {
        format = "%s %s %s/%s\n";
    }
    fprintf(stdout, format,
            what,
            inet_ntoa(addr),    netbios_ns_entry_group(entry),
            netbios_ns_entry_name(entry),
            netbios_ns_entry_type(entry)); fflush(stdout);
}

#ifndef PLATFORM_WINDOWS
static int list_shares_smb1(void *p_opaque,
                            char *name,
                            uint32_t ip) {
    struct watcher_options *options = (struct watcher_options *)p_opaque;
    struct in_addr  addr;
    smb_session   *session;
    smb_tid     tid;
    smb_fd      fd;

    session = smb_session_new();
    if (session == NULL)
        return 1;

    addr.s_addr = ip;

    int session_ret = smb_session_connect(session, name, 
                                          addr.s_addr, SMB_TRANSPORT_TCP);
    if (session_ret) {
        print_if((options->mode == MODE_TEST), "    Unable to connect to host %s\n", inet_ntoa(addr));
        return session_ret;
    }

    smb_session_set_creds(session, options->workgroup, options->username, options->password);
    int login_ret = smb_session_login(session);
    if (login_ret == DSM_SUCCESS) {
        if (smb_session_is_guest(session))
            print_if((options->mode == MODE_TEST), "    Logged in as GUEST\n");
        else
            print_if((options->mode == MODE_TEST), "    Successfully logged in\n");
    }
    else {
        print_if((options->mode == MODE_TEST), "    Auth failed %s\n", inet_ntoa(addr));
        return login_ret;
    }

    smb_share_list list;
    size_t count;
    int list_ret = smb_share_get_list(session, &list, &count);
    if (list_ret == DSM_SUCCESS) {
        print_if((options->mode == MODE_TEST), "        share count: %i\n", count);
    }
    else {
        print_if((options->mode == MODE_TEST), "    Unable to connect to share, ret value: %i\n", list_ret);
        if (list_ret == DSM_ERROR_NT) {
            uint32_t nt_status = smb_session_get_nt_status(session);
            print_if((options->mode == MODE_TEST), "    nt_status: %x\n", nt_status);
        }
      
        return list_ret;
    }

    char *format = "        share name: %s\n";
    if (options->mode == MODE_SHARES) {
        format = "%s\n";
        
        fprintf(stdout, "SUCCESS SMB1");
        print_if(smb_session_is_guest(session), " ISGUEST");
        fprintf(stdout, "\n"); fflush(stdout);
    }
    for (int i = 0; i < count; i++) {
        fprintf(stdout, format, smb_share_list_at(list, i)); fflush(stdout);
    }

    smb_share_list_destroy(list);
    smb_session_destroy(session);

    return 0;
}

int cb_status;

void se_cb(struct smb2_context *smb2, int status,
                void *command_data, void *p_opaque) {
        struct srvsvc_netshareenumall_rep *rep = command_data;
        struct watcher_options *options = (struct watcher_options *)p_opaque;
        int i;

        if (status) {
                print_if((options->mode == MODE_TEST), "    failed to enumerate shares [%d](%s) %s\n",
                       status, strerror(-status), smb2_get_error(smb2));
                cb_status = status;
                return;
        }

        print_if((options->mode == MODE_TEST), "        share count: %i\n", rep->ctr->ctr1.count);
        char *format = "        share name: %-20s %-20s";
        char *prefix = "     ";
        if (options->mode == MODE_SHARES) {
            format = "%s";
            prefix = " type:";
        }
        for (i = 0; i < rep->ctr->ctr1.count; i++) {
                printf(format, rep->ctr->ctr1.array[i].name,
                       rep->ctr->ctr1.array[i].comment);
                if ((rep->ctr->ctr1.array[i].type & 3) == SHARE_TYPE_DISKTREE) {
                        fprintf(stdout, "%sDISKTREE", prefix);
                }
                if ((rep->ctr->ctr1.array[i].type & 3) == SHARE_TYPE_PRINTQ) {
                        fprintf(stdout, "%sPRINTQ", prefix);
                }
                if ((rep->ctr->ctr1.array[i].type & 3) == SHARE_TYPE_DEVICE) {
                        fprintf(stdout, "%sDEVICE", prefix);
                }
                if ((rep->ctr->ctr1.array[i].type & 3) == SHARE_TYPE_IPC) {
                        fprintf(stdout, "%sIPC", prefix);
                }
                if (rep->ctr->ctr1.array[i].type & SHARE_TYPE_TEMPORARY) {
                        fprintf(stdout, "%sTEMPORARY", prefix);
                }
                if (rep->ctr->ctr1.array[i].type & SHARE_TYPE_HIDDEN) {
                        fprintf(stdout, "%sHIDDEN", prefix);
                }
                fprintf(stdout, "\n"); fflush(stdout);
        }

        smb2_free_data(smb2, rep);

        cb_status = 0;
}

static int list_shares_smb2(void *p_opaque,
                            char *name) {
    struct watcher_options *options = (struct watcher_options *)p_opaque;
    struct smb2_context *smb2;
    struct smb2_url *url;
    struct pollfd pfd;

    smb2 = smb2_init_context();
    if (smb2 == NULL) {
        print_if((options->mode == MODE_TEST), "    Failed to init context\n");
        return 1;
    }

    cb_status = 1;

    smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);
    if (options->username[0] != '\0') smb2_set_user(smb2, options->username);
    if (options->password[0] != '\0') smb2_set_password(smb2, options->password);

    int connect_ret = smb2_connect_share(smb2, name, "IPC$", NULL);
    if (connect_ret < 0) {
        print_if((options->mode == MODE_TEST), "    Failed to connect to IPC$. %s\n",
               smb2_get_error(smb2));
        return -connect_ret;
    }

    int enum_ret = smb2_share_enum_async(smb2, se_cb, p_opaque);
    if (enum_ret != 0) {
        print_if((options->mode == MODE_TEST), "    smb2_share_enum failed. %s\n", smb2_get_error(smb2));
        return -enum_ret;
    }

    if (options->mode == MODE_SHARES) {
        fprintf(stdout, "SUCCESS SMB2");
        print_if((smb_session_is_guest(smb2) == 1), " ISGUEST");
        fprintf(stdout, "\n"); fflush(stdout);
    }

    while (cb_status > 0) {
        pfd.fd = smb2_get_fd(smb2);
        pfd.events = smb2_which_events(smb2);

        int poll_ret = poll(&pfd, 1, 1000);
        if (poll_ret < 0) {
            print_if((options->mode == MODE_TEST), "    Poll failed");
            return errno;
        }
        if (pfd.revents == 0) {
            continue;
        }
        if (smb2_service(smb2, pfd.revents) < 0) {
            print_if((options->mode == MODE_TEST), "    smb2_service failed with : %s\n",
                   smb2_get_error(smb2));
            break;
        }
    }

    smb2_disconnect_share(smb2);
    smb2_destroy_context(smb2);
        
    return -cb_status;
}
static int list_shares(watcher_options *options,
                       char* name,
                       uint32_t ip) {
    bool test_mode = (options->mode == MODE_TEST);
    int ret = ROON_SMB_SUCCESS;

    print_if(test_mode, "  attempting to list shares over smb2 with credentials\n");
    ret = list_shares_smb2(options, name);
    print_if(test_mode, "  return value: %d\n", ret);
    if ((ret == ROON_SMB_SUCCESS) && (options->mode == MODE_SHARES)) return ROON_SMB_SUCCESS;

    print_if(test_mode, "  attempting to list shares over smb2 with credentials\n");
    ret = list_shares_smb1(options, name, ip);
    print_if(test_mode, "  return value: %d\n", ret);   
    if ((ret == ROON_SMB_SUCCESS) && (options->mode == MODE_SHARES)) return ROON_SMB_SUCCESS;
    
    if (test_mode) {
        struct watcher_options *guest_creds = malloc(sizeof(struct watcher_options));
        guest_creds->mode      = options->mode;
        guest_creds->workgroup = "";
        guest_creds->username  = "Guest";
        guest_creds->password  = "password";

        print_if(test_mode, "  attempting to list shares over smb2 as guest\n");
        ret = list_shares_smb2(guest_creds, name);
        print_if(test_mode, "  return value: %d\n", ret);
        if (ret == ROON_SMB_SUCCESS) return ROON_SMB_SUCCESS;
        
        print_if(test_mode, "  attempting to list shares over smb1 as guest\n");
        ret = list_shares_smb1(guest_creds, name, ip);
        print_if(test_mode, "  return value: %d\n", ret);
    }
    return ret;
}
#endif

static void on_entry_added(void *p_opaque,
                           netbios_ns_entry *entry) {
    struct watcher_options *options = (struct watcher_options *)p_opaque;
    print_entry("added", entry, options);
#ifndef PLATFORM_WINDOWS
    if (options->mode == MODE_TEST) {
        int list_ret = list_shares(options, netbios_ns_entry_name(entry), netbios_ns_entry_ip(entry));
    }
#endif
}

static void on_entry_removed(void *p_opaque,
                             netbios_ns_entry *entry) {
    struct watcher_options *options = (struct watcher_options *)p_opaque;
    print_entry("removed", entry, options);
}

static int usage() {
    fprintf(stdout, "Usage:\n");
    fprintf(stdout, "roon_smb_watcher test [workgroup] [username] [password]\n");
    fprintf(stdout, "roon_smb_watcher hosts [timeout]\n");
    fprintf(stdout, "roon_smb_watcher shares <name type> <server> [workgroup] [username] [password]\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "see README file for details\n");
    return ROON_SMB_NOT_SUPPORTED;
}

static int scan_hosts(watcher_options *options) {
    netbios_ns *ns;
    netbios_ns_discover_callbacks callbacks;

    ns = netbios_ns_new();

    callbacks.p_opaque = (void*)options;
    callbacks.pf_on_entry_added = on_entry_added;
    callbacks.pf_on_entry_removed = on_entry_removed;

    if (options->mode == MODE_TEST) fprintf(stdout, "Discovering...\nPress Enter to quit\n");
    int ret = netbios_ns_discover_start(ns,
                                        4,
                                        &callbacks);
    if (options->mode == MODE_TEST) fprintf(stdout, "return code from start: %i\n", ret);
    if (ret != 0) {
        fprintf(stdout, "ERROR Error while discovering local network\n");
        exit(ret);
    }

    getchar();

    netbios_ns_discover_stop(ns);

    return (0);
}

static int run_test(watcher_options *options) {
    return scan_hosts(options);
}

static int run_hosts(intmax_t freq, watcher_options *options) {    
    return scan_hosts(options);
}

#ifndef PLATFORM_WINDOWS
static int run_shares(char *name_type, char *name_or_ip, watcher_options *options) {
    char* name;
    uint32_t ip;
    
    netbios_ns *ns;
    ns = netbios_ns_new();
    
    if (strcmp(name_type, "IP") == 0) {
//        struct in_addr addr;
//        addr.s_addr = 
//        int parse_ret = inet_aton(AF_INET, name_or_ip, &addr);
//        ip = addr.s_addr;
        ip = inet_addr(name_or_ip);
        name = netbios_ns_inverse(ns, ip);
        if (name == NULL) {
            name = name_or_ip;
        }
    } else if (strcmp(name_type, "NAME") == 0) {
        name = name_or_ip;
        int fs_result = netbios_ns_resolve(ns, name_or_ip, NETBIOS_FILESERVER, &ip);
        if (fs_result != 0) {
            fs_result == netbios_ns_resolve(ns, name_or_ip, NETBIOS_WORKSTATION, &ip);
            if (fs_result != 0) {
                ip = 0;
            }
        }
    }

    return list_shares(options, name, ip);
}
#endif

static void set_credentials(int argc, char** argv, watcher_options *options) {
    int offset = 0;
    if (options->mode == MODE_SHARES) {
        offset = 2;
    }
    if (argc >= (4 + offset)) {
        options->workgroup = argv[1 + offset];
        options->username  = argv[2 + offset];
        options->password  = argv[3 + offset];
    } else if (argc == (3 + offset)) {
        options->workgroup = "";
        options->username  = argv[1 + offset];
        options->password  = argv[2 + offset];
    } else if (argc == (2 + offset)) {
        options->workgroup = "";
        options->username  = argv[1 + offset];
        options->password  = "";
    } else if (argc == (1 + offset)) {
        options->workgroup = "";
        options->username  = "";
        options->password  = "";
    }
}

int main(int argc, char** argv) {
    if (argc == 1) return usage();

    struct watcher_options *options = malloc(sizeof(struct watcher_options));

    if (strcmp(argv[1], "test") == 0) {
        if (argc > 5) return usage();
        options->mode = MODE_TEST;
        set_credentials(argc, argv, options);
        return run_test(options);
    } else if (strcmp(argv[1], "hosts") == 0) {
        if (argc > 3) return usage();
        options->mode = MODE_HOSTS;
        intmax_t freq = 0;
        if (argc == 3) freq = strtoimax(argv[2], NULL, 10);
        return run_hosts(freq, options);
#ifndef PLATFORM_WINDOWS        
    } else if (strcmp(argv[1], "shares") == 0) {
        if ((argc < 4) || (argc > 7)) return usage();
        options->mode = MODE_SHARES;
        set_credentials(argc, argv, options);
        return run_shares(argv[2], argv[3], options);
#endif
    } else {
        return usage();
    }
}
