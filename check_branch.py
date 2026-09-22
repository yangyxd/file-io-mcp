import os
import json
import hashlib

def run_cmd(cmd_str):
    """执行命令并返回输出"""
    result = os.popen(cmd_str)
    return result.read()

def simple_encrypt(text, key="git_auth_key"):
    """简单的XOR加密算法"""
    key = hashlib.md5(key.encode()).digest()
    encrypted = bytearray()
    for i, char in enumerate(text.encode()):
        encrypted.append(char ^ key[i % len(key)])
    return encrypted.hex()

def simple_decrypt(encrypted_text, key="git_auth_key"):
    """简单的XOR解密算法"""
    key = hashlib.md5(key.encode()).digest()
    encrypted_bytes = bytes.fromhex(encrypted_text)
    decrypted = bytearray()
    for i, byte in enumerate(encrypted_bytes):
        decrypted.append(byte ^ key[i % len(key)])
    return decrypted.decode()

def get_auth_file_path():
    """获取认证信息文件路径"""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), ".git_auth.json")

def load_auth_info():
    """加载已保存的认证信息"""
    auth_file = get_auth_file_path()
    if os.path.exists(auth_file):
        try:
            with open(auth_file, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_auth_info(auth_info):
    """保存认证信息到文件"""
    auth_file = get_auth_file_path()
    with open(auth_file, 'w') as f:
        json.dump(auth_info, f)

def extract_domain(url):
    """从URL中提取域名"""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return parsed.netloc

def check_branch(workPath, branch_name):
    """切换本地分支"""
    os.chdir(workPath)
    branch_list = run_cmd("git branch")
    print("分支列表：")
    print(branch_list)
    if branch_name in branch_list:
        print(f"开始切换分支到 {branch_name}")
        run_cmd(f"git checkout {branch_name}")
    else:
        print(f"分支 {branch_name} 不存在")

def check_branch_r(workPath, branch_name):
    """拉取远程分支并切换到本地"""
    os.chdir(workPath)
    branch_list = run_cmd("git branch -r")
    print("远程分支列表：")
    print(branch_list)
    if branch_name in branch_list:
        print(f"开始拉取远程分支 {branch_name} 并切换到本地")
        run_cmd(f"git checkout -b {branch_name} origin/{branch_name}")
    else:
        print(f"远程分支 {branch_name} 不存在")

def create_branch(workPath, branch_name):
    """创建新分支并切换到该分支"""
    os.chdir(workPath)
    branch_list = run_cmd("git branch")
    print("分支列表：")
    print(branch_list)
    if branch_name not in branch_list:
        print(f"开始创建分支 {branch_name}")
        run_cmd(f"git branch {branch_name}")
        print(f"开始切换分支到 {branch_name}")
        run_cmd(f"git checkout {branch_name}")
    else:
        print(f"分支 {branch_name} 已存在")

def update_branch(workPath):
    """检测当前目录或一级子目录是否有git仓库，获取当前分支并拉取更新"""
    print(f"当前目录: {workPath}")
    
    if is_git_repo(workPath):
        branch = get_current_branch(workPath)
        print(f"检测到git仓库，当前分支: {branch}")
        print(f"开始从远程拉取更新...")
        os.chdir(workPath)
        auth_info = load_auth_info()
        success = run_git_pull(auth_info)
        if success:
            print(f"{workPath} 更新完成")
        else:
            print(f"{workPath} 更新失败")
    else:
        print(f"{workPath} 不是git仓库")
    
    print("\n检查一级子目录:")
    for item in os.listdir(workPath):
        item_path = os.path.join(workPath, item)
        if os.path.isdir(item_path) and is_git_repo(item_path):
            branch = get_current_branch(item_path)
            print(f"\n检测到git仓库: {item_path}")
            print(f"当前分支: {branch}")
            print(f"开始从远程拉取更新...")
            os.chdir(item_path)
            auth_info = load_auth_info()
            success = run_git_pull(auth_info)
            if success:
                print(f"{item_path} 更新完成")
            else:
                print(f"{item_path} 更新失败")

def get_remote_url():
    """获取当前仓库的远程URL"""
    result = run_cmd("git config --get remote.origin.url")
    return result.strip()

def run_git_pull(auth_info):
    """执行git pull，支持HTTP认证，自动检测已保存的认证信息"""
    remote_url = get_remote_url()
    if not remote_url:
        print("无法获取远程仓库URL")
        return False
    
    remote_url = remote_url.rstrip('/')
    print(f"远程仓库URL: {remote_url}")
    domain = extract_domain(remote_url)
    print(f"提取的域名: {domain}")
    
    username = ""
    password = ""
    last_error = ""
    
    if domain in auth_info:
        try:
            username = auth_info[domain]['username']
            password = simple_decrypt(auth_info[domain]['password'])
            print(f"找到域名 {domain} 的已保存认证信息，用户名: {username}")
        except Exception as e:
            print(f"解密认证信息失败: {e}")
            username = ""
            password = ""
    else:
        print(f"未找到域名 {domain} 的已保存认证信息")
    
    if not username or not password:
        print("需要认证吗？(y/n)")
        need_auth = input().strip().lower()
        if need_auth == 'y':
            print("请输入用户名：")
            username = input().strip()
            print("请输入密码：")
            password = input().strip()
        else:
            username = ""
            password = ""
    
    if username and password:
        from urllib.parse import quote
        encoded_username = quote(username, safe='')
        encoded_password = quote(password, safe='')
        
        urls_to_try = []
        if remote_url.startswith("https://"):
            urls_to_try.append(remote_url.replace("https://", f"https://{encoded_username}:{encoded_password}@").rstrip('/'))
            urls_to_try.append(remote_url.rstrip('/'))
        elif remote_url.startswith("http://"):
            urls_to_try.append(remote_url.replace("http://", f"http://{encoded_username}:{encoded_password}@").rstrip('/'))
            urls_to_try.append(remote_url.replace("http://", f"https://{encoded_username}:{encoded_password}@").rstrip('/'))
            urls_to_try.append(remote_url.rstrip('/'))
            urls_to_try.append(remote_url.replace("http://", "https://").rstrip('/'))
        else:
            urls_to_try.append(remote_url.rstrip('/'))
        
        print(f"尝试的URL数量: {len(urls_to_try)}")
        for i, url in enumerate(urls_to_try):
            print(f"尝试第 {i+1}/{len(urls_to_try)} 个URL...")
            result = run_cmd(f"git pull {url}")
            if "fatal" not in result and ("Already up to date" in result or "Updating" in result or "Fast-forward" in result):
                print(f"成功！结果: {result}")
                if domain not in auth_info:
                    print(f"认证成功，是否保存该域名的认证信息？(y/n)")
                    save_choice = input().strip().lower()
                    if save_choice == 'y':
                        auth_info[domain] = {
                            'username': username,
                            'password': simple_encrypt(password)
                        }
                        save_auth_info(auth_info)
                        print(f"已保存域名 {domain} 的认证信息")
                return True
            last_error = result
            print(f"尝试失败: {last_error.strip()[:100]}...")
        
        print(f"\n所有尝试均失败，最后错误: {last_error.strip()}")
        if "HTTP/0.9" in last_error:
            print("提示：HTTP/0.9错误通常表示服务器配置问题、网络代理问题或防火墙拦截")
            print("建议：")
            print("1. 检查网络连接")
            print("2. 检查代理设置")
            print("3. 尝试使用SSH协议")
            print("4. 联系服务器管理员")
        return False
    else:
        urls_to_try = [remote_url]
        if remote_url.startswith("http://"):
            urls_to_try.append(remote_url.replace("http://", "https://"))
        
        for url in urls_to_try:
            result = run_cmd(f"git pull {url}")
            if "fatal" not in result:
                print(result)
                return True
            last_error = result
        
        print(f"拉取失败: {last_error.strip()}")
        if "unable to access" in last_error or "Authentication failed" in last_error:
            print("请重新运行并选择需要认证")
        return False

def is_git_repo(path):
    """检查路径是否为git仓库"""
    git_dir = os.path.join(path, ".git")
    return os.path.isdir(git_dir)

def get_current_branch(workPath):
    """获取当前分支名称"""
    os.chdir(workPath)
    result = run_cmd("git rev-parse --abbrev-ref HEAD")
    return result.strip()

def file_name(file_dir, operation, branch_name=None):
    """遍历子目录并执行相应操作"""
    for root, dirs, files in os.walk(file_dir):
        for name in dirs:
            # 过滤非项目目录
            if "." not in name and "test" not in name and "docs" not in name and "monitor" not in name and "zipkin" not in name:
                workPath = os.path.join(root, name)
                print(f"处理项目目录: {workPath}")
                if operation == "check_branch":
                    check_branch(workPath, branch_name)
                elif operation == "create_branch":
                    create_branch(workPath, branch_name)
                elif operation == "check_branch_r":
                    check_branch_r(workPath, branch_name)
                elif operation == "update_branch":
                    update_branch(workPath)
        break

def main():
    path = os.path.abspath(__file__)
    path = os.path.dirname(path)
    print("项目路径：" + path)

    print("请输入命令类型：0 切换分支 1 创建分支并切换到新分支 2 拉取远程分支到本地 3 批量更新远程分支代码")
    cmd = input()
    if cmd == '0':
        print("请输入要切换的分支：")
        version = input()
        file_name(path, "check_branch", version)
    elif cmd == '1':
        print("请输入要创建的分支：")
        version = input()
        file_name(path, "create_branch", version)
    elif cmd == '2':
        print("请输入要切换的分支：")
        version = input()
        file_name(path, "check_branch_r", version)
    elif cmd == '3':
        file_name(path, "update_branch")
    else:
        print("无效的命令")

if __name__ == "__main__":
    main()