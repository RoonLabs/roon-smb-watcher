project('roon-smb-watcher', ['c'],
    version: '0.1.0',
    license: ['LGPL2'],
    default_options: ['c_std=c99',
                      'warning_level=2',
                      'buildtype=release',
                      'b_ndebug=if-release'],
    meson_version: '>= 0.50.0')

conf_data = configuration_data()
conf_data.set_quoted('URANDOM', '/dev/urandom') #TODO
conf_data.set('_FORTIFY_SOURCE', 2,
              description: 'Define to 2 to get glibc warnings.')
conf_data.set('_FILE_OFFSET_BITS', 64,
              description: 'Define to 64 for large file support.')
conf_data.set('_DEFAULT_SOURCE', 1)

cc = meson.get_compiler('c')

test_args = ''

# Check headers
#if cc.has_header('bsd/string.h')
#  conf_data.set('HAVE_BSD_STRING_H', 1)
#endif
#
#if cc.has_header('alloca.h')
#  conf_data.set('HAVE_ALLOCA_H', 1)
#endif
#
#if cc.has_header('sys/queue.h')
#  conf_data.set('HAVE_SYS_QUEUE_H', 1)
#endif
#
#if cc.has_header('arpa/inet.h')
#  conf_data.set('HAVE_ARPA_INET_H', 1)
#endif
#
#if cc.has_header('sys/socket.h')
#  conf_data.set('HAVE_SYS_SOCKET_H', 1)
#endif
#
#if cc.has_header('sys/time.h')
#  conf_data.set('HAVE_SYS_TIME_H', 1)
#endif
#
#if cc.has_header('ifaddrs.h')
#  conf_data.set('HAVE_IFADDRS_H', 1)
#endif

warning_arguments = [
  '-Wall',
  '-Wsign-compare',
  '-Wextra',
  '-Wstrict-aliasing',
  '-Wstrict-overflow' ]

add_project_arguments(warning_arguments, language: 'c')

# Check functions
if host_machine.system() == 'linux'
  test_args += '-D_GNU_SOURCE'
  add_project_arguments('-DPLATFORM_LINUX', language: 'c')
elif host_machine.system() == 'darwin'
  add_project_arguments('-DPLATFORM_MACOSX', language: 'c')
else
  if host_machine.system() == 'windows'
    add_project_arguments('-DPLATFORM_WINDOWS', language: 'c')
  elif host_machine.system() == 'cygwin'
    add_project_arguments('-DPLATFORM_WINDOWS', language: 'c')
  endif
endif

compat_sources = []

deps = [
  dependency('threads'),
  dependency('libdsm'),
  dependency('libsmb2')
]

watcher_sources = [
  'src/roon_watcher.c'
 ]

#watcher_headers = [
#  'include/bdsm/netbios_defs.h',
#  'include/bdsm/netbios_ns.h',
#  'include/bdsm.h'
#]

includes = include_directories('.', 'include')

watcherobj = executable('roon_smb_watcher', watcher_sources,
                        dependencies: deps,
                        include_directories: includes)

