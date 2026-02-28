# Удаление предыдущей версии
conda env remove -n tentacula_env

# Создание окружения Conda для UNIX
conda env create -f environment_unix.yml -n tentacula_env

# Активация окружения
conda activate tentacula_env

# Упаковка окружения
conda-pack -n tentacula_env -o tentacula_env_unix.tar.gz

######################################################################################

# Удаление предыдущей версии
conda env remove -n tentacula_env

# Создание окружения Conda для Windows
conda env create -f environment_win.yml -n tentacula_env

# Активация окружения
conda activate tentacula_env

# Добавление Python-LDAP
python -m pip install C:\Users\admin\Downloads\python_ldap-3.4.5-cp312-cp312-win_amd64.whl

# Упаковка окружения
conda pack -n tentacula_env -o tentacula_env_win.zip --format zip