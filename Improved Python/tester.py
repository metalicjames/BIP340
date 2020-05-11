from schnorr import *

import csv
import os
import sys

def test_vectors_single(fpath) -> bool:
    all_passed = True
    with open(os.path.join(sys.path[0], fpath), newline='') as csvfile:
        reader = csv.reader(csvfile)
        reader.__next__()
        for row in reader:
            (index, seckey_hex, pubkey_hex, aux_rand_hex, msg_hex, sig_hex, result_str, comment) = row
            pubkey = bytes.fromhex(pubkey_hex)
            msg = bytes.fromhex(msg_hex)
            sig = bytes.fromhex(sig_hex)
            result = result_str == 'TRUE'
            print('\nTest vector', ('#' + index).rjust(3, ' ') + ':')
            if seckey_hex != '':
                seckey = bytes.fromhex(seckey_hex)
                pubkey_actual = pubkey_gen(seckey)
                if pubkey != pubkey_actual:
                    print(' * Failed key generation.')
                    print('   Expected key:', pubkey.hex().upper())
                    print('     Actual key:', pubkey_actual.hex().upper())
                aux_rand = bytes.fromhex(aux_rand_hex)
                try:
                    sig_actual = schnorr_sign(msg, seckey, aux_rand)
                    if sig == sig_actual:
                        print(' * Passed signing test.')
                    else:
                        print(' * Failed signing test.')
                        print('   Expected signature:', sig.hex().upper())
                        print('     Actual signature:', sig_actual.hex().upper())
                        all_passed = False
                except RuntimeError as e:
                    print(' * Signing test raised exception:', e)
                    all_passed = False
            result_actual = schnorr_verify(msg, pubkey, sig)
            if result == result_actual:
                print(' * Passed verification test.')
            else:
                print(' * Failed verification test.')
                print('   Expected verification result:', result)
                print('     Actual verification result:', result_actual)
                if comment:
                    print('   Comment:', comment)
                all_passed = False
    print()
    if all_passed:
        print('All test vectors passed.')
    else:
        print('Some test vectors failed.')
    return all_passed

def test_vectors_multi(fpath) -> bool:
    all_passed = True
    pubkeys = []
    msgs = []
    sigs = []
    with open(os.path.join(sys.path[0], fpath), newline='') as csvfile:
        reader = csv.reader(csvfile)
        reader.__next__()
        for row in reader:
            (index, seckey_hex, pubkey_hex, aux_rand_hex, msg_hex, sig_hex, result_str, comment) = row
            pubkey = bytes.fromhex(pubkey_hex)
            msg = bytes.fromhex(msg_hex)
            sig = bytes.fromhex(sig_hex)
            pubkeys.append(pubkey)
            msgs.append(msg)
            sigs.append(sig)
    test_passed = batch_verify(pubkeys, msgs, sigs)
    if test_passed:
        print('Batch verification successful')
    else:
        print('Batch verification failed')

if __name__ == '__main__':
    #test_vectors_single('test-vectors.csv')
    single_start = time()
    test_vectors_single('test-vectors-multi.csv')
    single_stop = time()
    single = single_stop-single_start
    multi_start = time()
    test_vectors_multi('test-vectors-multi.csv')
    multi_stop = time()
    multi = multi_stop-multi_start
    print('Single verification time: '+ str(round(single, 4)) + ' seconds')
    print('Batch verification time: '+ str(round(multi, 4)) + ' seconds')
