project('roon-smb-watcher', ['c'],
    version: '0.1.0',
    license: ['LGPL2'],
    default_options: ['c_std=c11',
                      'warning_level=2',
                      'buildtype=release',
                      'b_ndebug=if-release',
                      'default_library=static'],
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

deps = [
]

if (meson.is_cross_build())
  ws_lib = meson.get_cross_property('ws_lib', false)
  if (ws_lib != false)
    deps += cc.find_library(ws_lib)
  endif
endif

if host_machine.system() != 'windows' and host_machine.system() != 'cygwin'
  deps += subproject('libsmb2').get_variable('bin_dep')
  deps += dependency('threads')
endif

watcher_sources = [
  'src/roon_watcher.c'
 ]

includes = include_directories('.', 'include', 'subprojects/libdsm/include')

watcherobj = executable('roon_smb_watcher', watcher_sources,
                        #build_rpath: meson.source_root() + '/lib',
                        link_with: subproject('libdsm').get_variable('libdsm'),
                        dependencies: deps,
                        install: true,
                        install_dir:'bin',
                        include_directories: includes)

