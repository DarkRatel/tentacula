# Удаление предыдущей версии
conda env remove -n tentacula_env

# Создание окружения Conda
conda env create -f environment.yml -n tentacula_env

# Активация окружения
conda activate tentacula_env

# Отключено, поскольку Conda сохраняет все необходимые зависимости
# Установка зависимостей pip
# pip install -r app/requirements.txt

# Упаковка окружения
conda-pack -n tentacula_env -o tentacula_env.tar.gz