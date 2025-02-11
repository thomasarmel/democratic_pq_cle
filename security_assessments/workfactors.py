import math


n = 16018 # Code size
p = 8009 # Code dimension
t = 50 # Error count

# l, p, e1, e2 computed using https://link.springer.com/chapter/10.1007/978-3-642-29011-4_31
l = int(0.01722 * n)
psi = int(0.00311681 * n)
e1 = int(0.000232741 * n)
e2 = int(0.0000013983 * n)

psi1 = (psi // 2) + e1
psi2 = (psi1 // 2) + e2

r0 = l
r1 = int(math.log2(math.comb(psi, psi//2) * math.comb(p+l-psi, e1)))
r2 = int(math.log2(math.comb(psi1, psi1//2) * math.comb(p+l-psi1, e2)))


S1 = math.comb(p+l, psi1) >> r1

S2 = math.comb(p+l, psi2) >> r2
S3 = math.comb((p + l) // 2, psi2 //2)

C1 = int(math.pow(S1, 2) * math.pow(2, r1-r0))
C2 = int(math.pow(S2, 2) * math.pow(2, r2-r1))
C3 = int(math.pow(S3, 2)) >> r2

P_inv = math.comb(n, t) / (math.comb(p+l, psi) * math.comb(n - p - l, t - psi)) # Iterations count

T1 = max(S1, C1)
T2 = max(S2, C2)
T3 = max(S3, C3)

T = max(T1, T2, T3) # Time per iteration

WF_ISD = T * P_inv
print("ISD work factor: 2^(" + str(math.log2(WF_ISD)) + ")")

WF_DIST = WF_ISD // (n - p)
print("Key distinguishing work factor: 2^(" + str(math.log2(WF_DIST)) + ")")

WF_RECO = WF_ISD // (n - p)
print("Key recovery work factor: 2^(" + str(math.log2(WF_RECO)) + ")")

WF_DEC = WF_ISD // math.sqrt(p)
print("Decoding work factor: 2^(" + str(math.log2(WF_DEC)) + ")")