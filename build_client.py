import os
import sys
import subprocess
import shutil

def build_client():
    """将客户端打包成 exe 文件"""
    print("开始打包客户端...")
    
    # 确保安装了必要的依赖
    print("检查并安装依赖...")
    subprocess.call([sys.executable, "-m", "pip", "install", "pyinstaller", "requests", "python-docx", "PyPDF2", "openpyxl", "pywin32"])
    
    # 创建打包目录
    if not os.path.exists("dist"):
        os.makedirs("dist")
    
    # 使用 Python 模块方式调用 PyInstaller 而不是命令行
    print("正在打包客户端...")
    
    # 构建 PyInstaller 命令参数
    pyinstaller_args = [
        "--noconfirm",
        "--onefile",
        "--windowed",
        "--name=企业信息安全审计工具",
        "client/client.py"
    ]
    
    # 如果图标文件存在，添加图标参数
    if os.path.exists("client/icon.ico"):
        pyinstaller_args.extend(["--icon=client/icon.ico", "--add-data=client/icon.ico;."])
    
    # 使用 Python 模块方式调用 PyInstaller
    subprocess.call([sys.executable, "-m", "PyInstaller"] + pyinstaller_args)
    
    print("打包完成！")
    print(f"可执行文件位置: {os.path.abspath('dist/企业信息安全审计工具.exe')}")

if __name__ == "__main__":
    build_client()