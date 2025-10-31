# Создание окуружения Conda
conda env create -f environment.yml

# Активация окружения
conda activate tentacula

# Установка зависимостей pip
pip install -r app/requirements.txt

# Упаковка окружения
conda-pack -n tentacula -o tentacula.tar.gz --compress-level 9