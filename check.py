import requests
import os
import csv


requests.packages.urllib3.disable_warnings()

# 搜索项目
def search_projects():
    token = os.getenv("GH_TOKEN", "")
    headers = {
        "Authorization": f"Bearer {token}",
        "Connection": "close",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.119 Safari/537.36",
    }
    
    # Send a search request to GitHub API
    search_url = "https://api.github.com/search/repositories?q=nuclei-templates&sort=updated&page=1&per_page=100"
    response = requests.get(search_url, headers=headers, verify=False, allow_redirects=False).json()
    
    # Extract the list of projects from the response
    projects = [i['html_url'] for i in response.get("items", [])]
    
    # Return the list of projects
    return projects

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

def append_github_links(file_path, links):
    # 追加链接到CSV文件
    with open(file_path, 'a', newline='') as f:
        writer = csv.writer(f)
        for link in links:
            writer.writerow([link])  # 写入链接

def main():
    file_path = 'links.csv'
    links = read_github_links(file_path)
    projects = search_projects()
    new_links = [link for link in projects if link not in links and link != 'https://github.com/20142995/nuclei-templates']
    append_github_links(file_path, new_links)


# 运行主函数
if __name__ == '__main__':
    main()
