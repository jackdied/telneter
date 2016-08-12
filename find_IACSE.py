'''
Alternate strategies to find IAC+SE in a bytestring.

The payload looks like a 4+ byte blob:
  IAC SB <zero or more payload bytes> IAC SE

The tricky part is that an IAC in the payload is escaped to IAC IAC.
So the terminting IAC+SE is really the first SE that is preceded by
an *odd* number of IACs.

These functions do very little in loop a potentially large number of times.
The original dumb function took ~100ms to parse a 1 megabyte string.
Adding one function call per byte adds another ~80ms.
Adding one comparison operation per byte adds another ~30ms.

So look at as few bytes as possible and do as little as possible for each one.
Easier said than done -- if the whole payload is AICs you have to count them all.

In real life the payload will be small, maximum of tens of bytes.
But there was unittest that passed in a 1meg string and took 99% of the time
for the whole suite; so I wrote these to get that test down to ~0ms.
'''

from __future__ import print_function

from itertools import izip
import re
import time
from telnetlib import IAC, SB, SE, STATUS


all_finders = []
def register_finder(func):
    all_finders.append(func)
    return func

@register_finder
def find_simple(data):
    ''' The original (and slow) function.
        Scan from the left.
        - if the next two bytes are IAC+SE we are done.
        - elif the next two bytes are IAC+IAC i+=2
        - else i+=1
    '''

    # this turns out to be really slow, ~100ms on a 1M string.
    i = 0
    try:
        while True:
            if data[i] == IAC:
                if data[i+1] == SE:
                    return i  # found it!
                elif data[i+1] == IAC:  # escaped IAC
                    i += 2
                else:
                    i += 1
            else:
                i += 1
    except IndexError:
        return -1


@register_finder
def find_simple2(data):
    i = 0
    iacs = 0
    try:
        while True:
            if iacs % 2 and data[i] == SE:
                return i-1
            elif data[i] == IAC:
                iacs += 1
            else:
                iacs = 0
            i += 1
    except IndexError:
        return -1
    return -1


@register_finder
def find_simple3(data):
    # find the IAC+SE then increment backwards
    iacse_i = data.find(IAC+SE)
    if iacse_i == 0:
        return iacse_i

    try:
        while iacse_i >= 0:
            end = i = iacse_i - 1
            while data[i] == IAC:
                i -= 1
            if not (end - i) % 2:  # even number of preceding IACS
                return iacse_i
            else:
                iacse_i = data.find(IAC+SE, iacse_i+1)
    except IndexError:
        pass
    return -1


@register_finder
def find_regexp(haystack):
    # regexps speed things up, but not enough. ~25ms on a 1M string.
    # not an IAC followed by zero or an even number of IACs followed by IAC+SE
    want = re.compile('(?<!%s)(%s%s)*(%s%s)' % (IAC, IAC, IAC, IAC, SE))
    m = want.search(haystack)
    if not m:
        return -1
    return m.end() - 2


@register_finder
def find_regexp2(haystack):
    # regexps speed things up, but not enough. ~25ms on a 1M string.
    want = re.compile('%s+%s' % (IAC, SE))
    m = None
    for m in want.finditer(haystack):
        if (m.end() - m.start()) % 2 == 0:  # even number of chars
            return m.end() - 2
    return -1


@register_finder
def find_find(haystack):
    # simple bytes.find() works pretty well for the normal case. ~1ms on a 1M string.
    iaciac_i = haystack.find(IAC+IAC)
    iacse_i = haystack.find(IAC+SE)

    while iacse_i != -1:
        if iaciac_i == -1 or iaciac_i > iacse_i:
            break
        if iaciac_i+2 <= iacse_i:
            iaciac_i = haystack.find(IAC+IAC, iaciac_i+2)
        else:
            iacse_i = haystack.find(IAC+SE, iacse_i+2)
    return iacse_i


@register_finder
def find_hybrid(haystack):
    # hybrid of bytes.find() and regexp
    iaciac_i = haystack.find(IAC+IAC)
    iacse_i = haystack.find(IAC+SE)

    loops = 0
    while iacse_i != -1:
        if iaciac_i == -1 or iaciac_i > iacse_i:
            break
        if iaciac_i+2 <= iacse_i:
            iaciac_i = haystack.find(IAC+IAC, iaciac_i+2)
        else:
            iacse_i = haystack.find(IAC+SE, iacse_i+2)
        loops += 1
        if loops > 100:
            # pathologically weird case, the regexp version is good for those
            return find_regexp2(haystack)
    return iacse_i


@register_finder
def find_rfind(haystack):
    ''' the most complicated strategy (which is why there are lots of comments) '''
    iacse_i = haystack.find(IAC+SE)
    iaciac_j = haystack.rfind(IAC+IAC, 0, iacse_i+1)

    iaciac_pairs = set()
    maybe_iaciac_pairs = set()

    while iacse_i != -1:
        if (iacse_i == -1 or  # IACSE not found
            iaciac_j == -1 or  # IACSE found, no IACIAC before it
            iaciac_j != iacse_i-1):  # IACIAC not overlapping IACSE
            return iacse_i

        while (iaciac_j not in iaciac_pairs and  # IACIAC not already tested
               haystack[iaciac_j:iaciac_j+2] == IAC+IAC):  # possibly blocking
            maybe_iaciac_pairs.add(iaciac_j)
            assert iaciac_j >= 0, (iacse_i, iaciac_j, iaciac_pairs)
            iaciac_j -= 2

        # odd number of IACs followed by SE means the IAC+SE is good
        # even number of IACs followed by SE means the IACs are all escaped
        if (iaciac_j == -1 or  # decremented by two from 1 to -1, only one IAC
            haystack[iaciac_j:iaciac_j+2].count(IAC) == 1):
            return iacse_i
        # it was an even numbered block of IACS (i.e. all escaped)
        iaciac_pairs |= maybe_iaciac_pairs
        maybe_iaciac_pairs = set()

        # find the next candidate IACSE
        iacse_i = haystack.find(IAC+SE, iacse_i+1)
        # rfind an IACIAC before it
        iaciac_j = haystack.rfind(IAC+IAC, 0, iacse_i+1)
        if iacse_i == -1:  # no new IACSE found
            return -1
        elif iaciac_j in iaciac_pairs:  # already tested and found acceptable
            return iacse_i
        assert iaciac_j >= -1 and iacse_i >= -1
    return -1


@register_finder
def find_replace(data):
    ''' extremely simple and fast search (at the expense of a full in memory copy) '''
    ndata = data.replace(IAC+IAC, ':)')
    return ndata.find(IAC+SE)


@register_finder
def find_itertools(data):
    it1 = iter(data)
    it2 = iter(data)
    try:
        next(it2)
        enumerated_pairs = enumerate(izip(it1, it2))
        for i, pair in enumerated_pairs:
            if pair == (IAC, IAC):
                # skip ahead an extra byte each to avoid IAC+IAC+SE
                next(enumerated_pairs)
            elif pair == (IAC, SE):
                return i
    except StopIteration:
        pass
    return -1


def speed_regressions():
    # for large SB payloads it is easy to do a very bad & slow parse
    # this test compares all the IAC+SE parsers.
    
    SIZE = 1024
    big_plain = 'x' * 1024 * SIZE
    big_iacs = ('xxxxxx' + IAC + IAC) * 128 * SIZE
    all_iacs = (IAC+IAC) * 512 * SIZE
    fake_iacses = ('xxxxx' + IAC + IAC + SE) * 128 * SIZE
    all_ses = SE*1024*SIZE
    blobs = [big_plain, big_iacs, all_iacs, fake_iacses, all_ses]

    print(map(len, blobs))
    results = []
    answers = []
    for func in all_finders:
        times_row = []
        answer_row = []
        for blob in blobs:
            start = time.time()
            ans = func(IAC+SB+STATUS + blob + IAC+SE)
            end = time.time()
            answer_row.append(ans)
            times_row.append('\t%6.3f' % (end - start))
        results.append(times_row)
        answers.append(answer_row)

    correct = answers[0]
    i = 1
    for also_correct in answers[1:]:
        i += 1
        assert correct == also_correct, (correct, also_correct)

    print(' ' * 18, ''.join(['\txxxxxx', '\txxxxII', '\tIIIIII', '\tIISIIS', '\tSSSSSS']))
    for func, times in zip(all_finders, results):
        print(func.__name__.ljust(20, ' '), ''.join(times))

if __name__ == '__main__':
    speed_regressions()
