import math
import numpy
import scipy

n = 16018
p = 8009
t = 50
w = 100

def not_rho():
    return sum(math.comb(w, l) * math.comb(n-w, t-l) / math.comb(n, t) for l in range(1, t+1, 2))

def f(_n, _p, k):
    print(scipy.special.comb(_n, k, exact=True) * numpy.pow(_p, k))
    return scipy.special.comb(_n, k) * numpy.pow(_p, k) * numpy.pow(1 - _p, _n - k)

nrho = not_rho()

proba_f = scipy.stats.binom(p, nrho)

total_dfr = 0.0

for line in open("weight_50.txt"):
    sline = line.split()
    error_count = int(sline[0])
    assert error_count == t
    syndrome_weight = int(sline[1])
    dfr_proba = float(sline[2])
    total_dfr += dfr_proba * proba_f.pmf(syndrome_weight)

print("DFR:", total_dfr, "\nSecurity level:", -math.log2(total_dfr))
