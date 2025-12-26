# Удаление предыдущей версии
conda env remove -n tentacula_env

# Создание окружения Conda для UNIX
conda env create -f environment_unix.yml -n tentacula_env

# Активация окружения
conda activate tentacula_env

# Отключено, поскольку Conda сохраняет все необходимые зависимости
# Установка зависимостей pip
# pip install -r app/requirements.txt

# Упаковка окружения
conda-pack -n tentacula_env -o tentacula_env.tar.gz