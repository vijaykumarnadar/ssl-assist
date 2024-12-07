import os
import shutil
import subprocess


global updated
updated = 0

def delete_existing_directory(directory_path):
    if os.path.exists(directory_path):
        shutil.rmtree(directory_path)
        print("Existing testssl-assist tool removed.")
        global updated
        updated = 1


def append_to_shell_config(shell_config_path, content):
    if os.path.exists(shell_config_path):
        with open(shell_config_path, 'r+') as shell_config:
            content_already_exists = any(content in line for line in shell_config)
            if not content_already_exists:
                shell_config.write(content)

def reload_shell_config(shell_config_path):
    if os.path.exists(shell_config_path):
        command = f'source {shell_config_path}'
        subprocess.run(command, shell=True, executable='/bin/bash')

# Define the installation path
install_path = os.path.expanduser('~/.testssl-assist')

# Delete the installation directory if it already exists
delete_existing_directory(install_path)

# Create the installation directory
os.makedirs(install_path)

# Current directory
current_directory = os.getcwd()

# Install requirements
requirements_path = os.path.join(current_directory, 'requirements.txt')
if os.path.exists(requirements_path):
    subprocess.check_call(['pip', 'install', '-r', requirements_path])

# Copy necessary files
for filename in os.listdir(current_directory):
    src_path = os.path.join(current_directory, filename)
    if filename in ['setup.py', 'requirements.txt']:
        continue
    dst_path = os.path.join(install_path, filename)
    if os.path.isdir(src_path):
        shutil.copytree(src_path, dst_path)
    elif os.path.isfile(src_path):
        shutil.copy(src_path, dst_path)
        os.chmod(dst_path, 0o755)

# Update shell configs
bashrc_path = os.path.expanduser('~/.bashrc')
zshrc_path = os.path.expanduser('~/.zshrc')
path_export_string = f'\nexport PATH="$PATH:{install_path}"'
alias_command_string = f"\nalias testssl-assist='python3 {os.path.join(install_path, 'main.py')}'"

append_to_shell_config(bashrc_path, path_export_string)
append_to_shell_config(bashrc_path, alias_command_string)
append_to_shell_config(zshrc_path, path_export_string)
append_to_shell_config(zshrc_path, alias_command_string)

reload_shell_config(bashrc_path)
reload_shell_config(zshrc_path)

if updated == 0:
    print("Installation complete. Changes applied. The tool can be accessed using 'testssl-assist' command")

else:
    print("Testssl-assist successfully updated!!")
