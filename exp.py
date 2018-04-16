# coding=utf-8

import os, string, shutil, re
import pefile
import wx


def TEST__():
    PEfile_Path = r"1.exe"
    pe = pefile.PE(PEfile_Path)
    # print(PEfile_Path)
    print(type(pe))

    f = open("1_analyze.txt", "w+")
    f.flush()
    f.write(str(pe))
    f.close()

    for section in pe.sections:
        if ".text" in str(section):
            print(section)


class MyFrame(wx.Frame):
    def __init__(self):
        j = 1
        wx.Frame.__init__(self, None, -1, u"PE 文件 简单解析 —————— 罗天涵", size=(1000, 700))
        panel = wx.Panel(self, -1)

        wx.StaticText(panel, -1, u"提示", pos=(20, 18))
        self.hint = wx.TextCtrl(panel, 1, "", pos=(50, 10), size=(300, 25))

        self.outputtext = wx.TextCtrl(panel, 1, "", pos=(380, 10), size=(400, 600), style=wx.TE_MULTILINE)

        self._load_file = wx.Button(parent=panel, label=u"导入文件", pos=(30, 10 + j * 45), size=(100, 28))
        self.Bind(wx.EVT_BUTTON, self.load_file, self._load_file)
        self.path = wx.TextCtrl(panel, 1, u"路径...", pos=(150, j * 45 + 10), size=(200, 28))

        j += 1

        self._static_analyze = wx.Button(parent=panel, label=u"生成pe文件分析报告", pos=(30, 10 + j * 45), size=(150, 28))
        self.Bind(wx.EVT_BUTTON, self.static_analyze, self._static_analyze)
        j += 1

        self._dll_import = wx.Button(parent=panel, label=u"pe文件DLL & API 分析", pos=(30, 10 + j * 45), size=(150, 28))
        self.Bind(wx.EVT_BUTTON, self.dll_import, self._dll_import)
        j += 1

        self._section_analyze = wx.Button(parent=panel, label=u"pe文件 Section 解析", pos=(30, 10 + j * 45), size=(150, 28))
        self.Bind(wx.EVT_BUTTON, self.section_analyze, self._section_analyze)
        j += 1

    def load_file(self, event):
        filesFilter = "exe (*.exe)|*.exe|" "All files (*.*)|*.*"
        fileDialog = wx.FileDialog(self, message=u"选择单个文件", wildcard=filesFilter, style=wx.FD_OPEN)
        dialogResult = fileDialog.ShowModal()
        if dialogResult != wx.ID_OK:
            return
        path = fileDialog.GetPath()
        self.path.SetLabel(path)

    def static_analyze(self, event):
        path = self.path.GetLabel()
        print (path)
        try:
            x = PE_Analyze(path)
            name = x.static_analyze()
            self.hint.SetValue(u"文件文件分析成功，报告位于目录文件的 {name} 中".format(name=name))
        except pefile.PEFormatError:
            self.hint.SetValue(u"无法读取DOS头部，请换一个文件")
        except:
            self.hint.SetValue(u"未知错误")

    def dll_import(self, event):
        path = self.path.GetLabel()
        print (path)
        try:
            x = PE_Analyze(path)
            result = x.dll_list_assistant(x.dll_import())
            self.outputtext.SetValue(result)
            self.hint.SetValue(u"文件文件分析成功")
        except pefile.PEFormatError:
            self.hint.SetValue(u"无法读取DOS头部，请换一个文件")
        except:
            self.hint.SetValue(u"未知错误")

    def section_analyze(self, event):
        path = self.path.GetLabel()
        print (path)
        try:
            x = PE_Analyze(path)
            x.Section_analyze()
            self.outputtext.SetValue(
                x.text.__str__() + "\n" + x.data.__str__() + "\n" + x.idata.__str__() + "\n" + x.rsrc.__str__())
            self.hint.SetValue(u"文件文件分析成功")
            if x.upx == True:
                self.hint.SetValue(u"检测到UPX壳,尝试打印upx壳数据")
                UPX_result = ""
                for i in x.upx_detail:
                    UPX_result += i.__str__() + "\n"
                self.outputtext.SetValue(UPX_result)
        except pefile.PEFormatError:
            self.hint.SetValue(u"无法读取DOS头部，请换一个文件")


class PE_Analyze:
    def __init__(self, path):
        if path != None:
            self.PEfile_Path = path
        self.data = ""
        self.idata = ""
        self.text = ""
        self.rsrc = ""
        self.upx = False
        self.upx_detail = []

    def run(self):
        pass

    def static_analyze(self):
        pe = pefile.PE(self.PEfile_Path)
        x = self.PEfile_Path.split("\\")[-1].replace(".", "_")
        f = open(x + "_analyze.txt", "w+")
        f.flush()
        f.write(str(pe))
        f.close()
        return x + "analyze.txt"

    def Section_analyze(self):
        pe = pefile.PE(self.PEfile_Path)
        other_section = []
        for section in pe.sections:
            if ".data" in str(section):
                self.data = section
            elif ".text" in str(section):
                self.text = section
            elif ".idata" in str(section):
                self.idata = section
            elif ".rsrc" in str(section):
                self.rsrc = section
            elif "UPX" or "upx" in str(section):
                self.upx = True
                for i in range((ord("0")), (ord("9"))):
                    if "UPX" + chr(i) in str(section):
                        self.upx_detail.append(section)
            else:
                temp = section
                other_section.append(temp)
        return other_section

    def dll_import(self):
        pe = pefile.PE(self.PEfile_Path)
        result_dll = {}
        for importeddll in pe.DIRECTORY_ENTRY_IMPORT:
            ##or use
            # print pe.DIRECTORY_ENTRY_IMPORT[0].dll
            result_dll_api = []
            for importedapi in importeddll.imports:
                result_dll_api.append(importedapi.name)
            result_dll[importeddll.dll] = result_dll_api
        return result_dll
        ##or use
        # print pe.DIRECTORY_ENTRY_IMPORT[0].imports[0].name

    def dll_list_assistant(self, result_dll):
        result_string = ""
        for dll in result_dll.keys():
            result_string = result_string + "DLL :::: " + str(dll) + "\n"
            for api in result_dll[dll]:
                result_string = result_string + "==>  " + str(api) + "\n"
        return result_string


def wx_start():
    app = wx.App()
    frame = MyFrame()
    frame.Show(True)
    app.MainLoop()


if __name__ == '__main__':
    wx_start()
'''
if __name__ == '__main__':
    x = PE_Analyze("1")
    z = x.Section_analyze()
    for i in z:
        print(i)
    print(x.idata)
    print(x.dll_import())
    dict = x.dll_import()
    print (x.dll_list_assistant(result_dll=dict))
'''
