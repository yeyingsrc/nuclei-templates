import os
import re
import csv
import shutil
import asyncio
import tempfile
import subprocess
import requests
import zipfile

requests.packages.urllib3.disable_warnings()

# 从文件中读取GitHub项目链接
def read_github_links(file_path):
    links = []

    # 读取CSV文件
    with open(file_path, 'r') as f:
        reader = csv.reader(f)
        next(reader)  # 跳过标题行
        for row in reader:
            if row[0].startswith('https://github.com'):
                links.append(row[0])  # 提取链接并添加到列表中
    return links

# 遍历临时目录中的.yaml文件
def process_yaml_files(temp_directory):
    # 创建目标文件夹
    target_directory = os.path.join(os.getcwd(), 'Other')
    os.makedirs(target_directory, exist_ok=True)

    # 遍历临时目录
    for root, _, files in os.walk(temp_directory):
        for file in files:
            if file.endswith('.yaml'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf8') as f:
                        content = f.read()
                except:
                    continue

                # 判断文件内容是否包含关键字
                if len([tag for tag in ['id:', 'info:', 'name:', 'author:', 'severity:', 'description:', 'tags:', 'requests:', 'matchers:'] if tag in content]) > 5:
                    # 判断文件名是否匹配CVE-\d{4}
                    match = re.match(r'CVE-\d{4}', file,re.I)
                    if match:
                        target_folder = os.path.join(
                            os.getcwd(), match.group().upper())
                        os.makedirs(target_folder, exist_ok=True)
                        target_path = os.path.join(target_folder, file)
                    else:
                        target_path = os.path.join(target_directory, file)

                    # 复制文件到目标路径
                    shutil.copy2(file_path, target_path)
                else:
                    # 移动文件到目标路径
                    target_path = os.path.join(target_directory, file)
                    shutil.move(file_path, target_path)

# 扫描冲突的文件并自动重命名
def handle_filename_conflicts(directory):
    files = os.listdir(directory)
    filename_counts = {}

    for file in files:
        if os.path.isfile(os.path.join(directory, file)):
            filename, ext = os.path.splitext(file)
            filename_lower = filename.lower()

            if filename_lower in filename_counts:
                count = filename_counts[filename_lower]
                new_filename = f"{filename}_{count}{ext}"
                filename_counts[filename_lower] += 1
            else:
                new_filename = file
                filename_counts[filename_lower] = 1

            if new_filename != file:
                old_path = os.path.join(directory, file)
                new_path = os.path.join(directory, new_filename)
                os.rename(old_path, new_path)
                print(f"Renamed {file} to {new_filename}")

# 统计每个子目录下的文件数量
def count_files():
    # 当前目录路径
    current_directory = os.getcwd()

    # 获取当前目录下的子目录列表
    subdirectories = [name for name in os.listdir(
        current_directory) if os.path.isdir(os.path.join(current_directory, name)) and name not in ['.github','.git']]
    
    # 按templates type升序排序
    subdirectories = sorted(subdirectories)

    # 表格标题
    table_header = "| templates type | templates conut |\n| --- | --- |"
    table_rows = []
    total = 0
    # 遍历子目录并统计文件数量
    for subdir in subdirectories:
        subdir_path = os.path.join(current_directory, subdir)
        handle_filename_conflicts(subdir_path)
        file_count = len(os.listdir(subdir_path))
        total += file_count
        table_row = f"| {subdir} | {file_count} |"
        table_rows.append(table_row)
    table_row = f"| Total | {total} |"
    table_rows.append(table_row)
    # 将结果写入README.md文件
    with open('README.md', 'w', encoding='utf8') as f:
        # 写入表格标题
        f.write(f"{table_header}\n")

        # 写入表格内容
        for row in table_rows:
            f.write(f"{row}\n")

# 校验yaml文件
def nuclei_validate(temp_directory):
    # 当前目录路径
    current_directory = os.getcwd()
    nuclei_path = download_extract_executable(temp_directory)
    command = f'{nuclei_path} -validate -t {current_directory}'
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        output = e.output
    err_pattern = r"Error occurred (?:loading|parsing) template (.*?)\:"
    for err_match in re.findall(err_pattern, output):
        file_path = err_match.replace("\\", "/") # 转换文件路径中的反斜杠
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"Deleted file: {file_path}")
    warn_pattern = r"Found duplicate template ID during validation '(.*?)' => '(.*?)'\:"
    for warn_match in re.findall(warn_pattern, output):
        old_path = warn_match[0].replace("\\", "/")
        new_path = warn_match[1].replace("\\", "/")
        if os.path.exists(old_path):
            os.rename(old_path, new_path)
            print(f"Renamed file: {old_path} to {new_path}")


# 下载nuclei
def download_extract_executable(temp_directory):
    token = os.getenv("GH_TOKEN", "")
    headers = {
        "Authorization": f"Bearer {token}",
        "Connection": "close",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.119 Safari/537.36",
    }
    # 发送请求获取最新的 release 信息
    release_info = requests.get("https://api.github.com/repos/projectdiscovery/nuclei/releases/latest",headers=headers,verify=False,allow_redirects=False).json()
    assets = release_info.get('assets', [])
    download_url = None
    for asset in assets:
        if asset.get('name', '').endswith("linux_amd64.zip"):
            download_url = asset.get('browser_download_url')
            break
    if not download_url:
        return None
    
    # 下载压缩包
    response = requests.get(download_url,headers=headers,verify=False)
    if response.status_code != 200:
        return None
    
    
    # 保存压缩包到临时目录
    zip_file_path = os.path.join(temp_directory, "executable.zip")
    with open(zip_file_path, 'wb') as f:
        f.write(response.content)
    
    # 解压压缩包
    extract_dir = os.path.join(temp_directory, "extracted")
    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)
    
    # 添加执行权限
    executable_path = os.path.join(extract_dir, "nuclei")
    os.chmod(executable_path, 0o755)
    
    # 返回可执行文件的完整路径
    return executable_path

# 克隆GitHub项目到指定目录
async def clone_github_project(link, save_directory):
    # 提取项目名称
    project_name = link.split('/')[-1].replace('.git', '')

    # 构建保存路径
    save_directory = os.path.join(save_directory, f"{project_name}")
    os.makedirs(save_directory, exist_ok=True)

    # 构建克隆命令
    clone_command = f'git clone {link} {save_directory}'

    # 执行克隆命令
    process = await asyncio.create_subprocess_shell(clone_command)
    await process.wait()

# 克隆GitHub项目列表
async def clone_github_projects(links, temp_directory):
    tasks = []
    for index, link in enumerate(links, start=1):
        # 创建每个克隆任务的协程对象
        task = clone_github_project(
            link, os.path.join(temp_directory, str(index)))
        tasks.append(task)

    # 并发执行所有协程任务
    await asyncio.gather(*tasks)

# 主函数
async def main():
    # 输入文件路径
    file_path = 'links.csv'

    # 创建临时目录
    temp_directory = tempfile.mkdtemp()

    # 读取GitHub项目链接
    github_links = read_github_links(file_path)

    # 克隆GitHub项目到指定目录
    await clone_github_projects(github_links, temp_directory)

    # 遍历临时目录中的.yaml文件
    process_yaml_files(temp_directory)

    # 校验yaml文件
    nuclei_validate(temp_directory)

    # 统计每个子目录下的文件数量
    count_files()
    
# 运行主函数
if __name__ == '__main__':
    asyncio.run(main())
