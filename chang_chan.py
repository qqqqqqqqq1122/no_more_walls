import os

REPO_PATH = "G:/try/clash-nodes1"  # 你的 GitHub 仓库路径
FILE_SRC = r"G:\try\NoMoreWalls\list.yml"

try:
    print("🚀 正在上传配置到 GitHub...")
    os.chdir(REPO_PATH)

    # 拷贝 list.yml 到仓库目录
    os.system(f'copy /Y "{FILE_SRC}" list.yml')

    # 仅在有变更时才提交
    os.system('git add list.yml')
    commit_status = os.system('git diff --cached --quiet || git commit -m "更新节点"')
    if commit_status == 0:
        os.system("git push origin main")
        print("✅ 成功上传到 GitHub！")
    else:
        print("⚠️ 没有变化，不需要提交。")

except Exception as e:
    print("❌ 上传失败：", e)