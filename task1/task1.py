import hashlib
import json


# Напишите программу, которая выполняет хеширование нескольких блоков. Блоки записаны в json файл.
# Программа должна формировать на выходе текстовый файл с хешами блоков.
def calculate_hash(block):
    # Преобразование блока в строку для хеширования
    block_string = json.dumps(block, sort_keys=True).encode()
    return hashlib.sha256(block_string).hexdigest()


def read_blocks_from_json(file_path):
    # Чтение блоков из файла
    with open(file_path, 'r') as file:
        blocks = json.load(file)
    return blocks


def write_hashes_to_file(hashes, file_path):
    # Запись хешей в текстовый файл
    with open(file_path, 'w') as file:
        for block_hash in hashes:
            file.write(block_hash + '\n')


def main():
    # Путь к JSON файлу с блоками
    input_json_file = 'task1.json'
    # Путь к выходному текстовому файлу с хешами
    output_txt_file = 'task1.txt'

    # Чтение блоков из JSON файла
    blocks = read_blocks_from_json(input_json_file)

    # Вычисление хешей для каждого блока
    hashes = []
    for block in blocks:
        block_hash = calculate_hash(block)
        hashes.append(block_hash)

    # Запись хешей в текстовый файл
    write_hashes_to_file(hashes, output_txt_file)

    print(f"Хеши блоков успешно записаны в файл {output_txt_file}")

if __name__ == "__main__":
    main()
