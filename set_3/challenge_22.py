# https://cryptopals.com/sets/3/challenges/22
# Crack an MT19937 seed

from challenge_21 import RNG
import time
import random


def rand():
    wait_seconds = random.randint(40, 1000)
    print(f'Waiting {wait_seconds} seconds to generate unix timestamp seed....')
    time.sleep(wait_seconds)
    seed = int(time.time())

    print('Actual seed: ', seed)
    rng = RNG(seed)

    wait_seconds = random.randint(40, 1000)
    print(f'Waiting {wait_seconds} seconds to generate random number....')
    time.sleep(wait_seconds)
    return rng.rand() & 0xffffffff

if __name__ == '__main__':
    # From the 32 bit output, we will recover the seed
    out = rand()

    cand_count = 1
    candidate_seed = int(time.time())
    candidate_rand = None

    while candidate_rand != out:
        rng = RNG(candidate_seed)
        candidate_rand = rng.rand() & 0xffffffff

        if cand_count % 1000 == 0:
            print(f'Number of candidate seeds tried: {cand_count}')

        if candidate_rand != out:
            candidate_seed -= 1
            cand_count += 1

    print('Recovered seed:', candidate_seed)
