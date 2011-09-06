# -*- mode: python -*-
projpath = os.path.dirname(os.path.abspath(SPEC))

def get_plugins(list):
    
    for item in list:
        if item[0].startswith('templates.template_files') and not (item[0] == 'templates.template_files' and '__init__.py' in item[1]):
            yield item
        elif item[0].startswith('reporting.report_formats') and not (item[0] == 'reporting.report_formats' and '__init__.py' in item[1]):
            yield item

'''
def remove_pyc_svn(list):

    fd = open("C:/users/a/desktop/remove.txt", "a+")
    for item in list:
    
        if item[0].find(".svn") != -1 or item[1].find(".svn") != -1:
            fd.write("--%s\n" % str(item))
            yield item
            
        elif item[0].endswith(".pyc") != -1 and item[1].find("regdecoder") != -1:
            fd.write("%s\n" % str(item))
            yield item
            
    fd.close()
'''
  
exeext = ".exe" if 'win' in sys.platform else ""

a = Analysis([os.path.join(HOMEPATH,'support\\_mountzlib.py'), os.path.join(CONFIGDIR,'support\\useUnicode.py'),  os.path.join(projpath, 'guimain.py')],
            pathex = [HOMEPATH],
            hookspath = [os.path.join(projpath, 'pyinstaller')])
              
pyz = PYZ(a.pure - set(get_plugins(a.pure)), name = os.path.join(BUILDPATH, 'regdecoder.pkz'))

plugins = Tree(os.path.join(projpath, 'reporting', 'report_formats'), 'reportingg')
plugins = plugins + Tree(os.path.join(projpath, 'templates', 'template_files'), 'templatess')

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          plugins,
          name = os.path.join(projpath, 'dist', 'pyinstaller', 'regdecoder' + exeext),
          debug = 0,
          strip = False,
          upx = False,
          icon = "",
          console = 1)

