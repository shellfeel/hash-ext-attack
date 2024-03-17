import sys

from loguru import logger

from common.HashExtAttack import HashExtAttack

def main():
    hash_ext_attack = HashExtAttack()
    logger.remove()
    logger.add(sys.stderr, level="INFO")
    hash_ext_attack.input_run()

if __name__ == '__main__':
    main()