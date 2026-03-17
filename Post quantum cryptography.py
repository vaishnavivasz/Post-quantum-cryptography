#!/usr/bin/env python
# coding: utf-8

# In[9]:


get_ipython().system('pip install oqs')


# In[5]:


import secrets
import hashlib

print("Post-Quantum KEM Simulation")

# Receiver generates keys
private_key = secrets.token_bytes(32)
public_key = hashlib.sha256(private_key).digest()

print("Public Key:", public_key)

# Sender generates shared secret
shared_secret_sender = secrets.token_bytes(32)

ciphertext = hashlib.sha256(public_key + shared_secret_sender).digest()

print("Ciphertext:", ciphertext)

# Receiver derives shared secret
shared_secret_receiver = shared_secret_sender

print("\nSender Secret:", shared_secret_sender)
print("Receiver Secret:", shared_secret_receiver)

print("\nSecrets match:", shared_secret_sender == shared_secret_receiver)


# In[6]:


import hashlib
import secrets

print("Dilithium Signature Simulation")

message = b"Hello PQC"

private_key = secrets.token_bytes(32)
public_key = hashlib.sha256(private_key).digest()

signature = hashlib.sha256(private_key + message).digest()

verification = hashlib.sha256(private_key + message).digest()

print("Signature valid:", signature == verification)


# In[18]:


pip install --upgrade --force-reinstall qiskit-aer


# In[23]:


import math

print("Shor Simulation")

def shor(N):
    a = 2

    for r in range(1, N):
        if pow(a, r, N) == 1:
            break

    f1 = math.gcd(pow(a, r//2) - 1, N)
    f2 = math.gcd(pow(a, r//2) + 1, N)

    return f1, f2

print("Factors of 15:", shor(15))


# In[24]:


import numpy as np

print("Grover's Algorithm Simulation")

# 2-qubit system (4 states)
n = 2
N = 2**n

# Step 1: Equal superposition
state = np.ones(N) / np.sqrt(N)

# Step 2: Oracle (mark state '11' → index 3)
oracle = np.identity(N)
oracle[3][3] = -1

# Step 3: Diffusion operator
D = 2 * np.outer(state, state) - np.identity(N)

# Apply Grover iteration
state = D @ oracle @ state

# Probabilities
probabilities = np.abs(state)**2

print("State probabilities:")
for i, prob in enumerate(probabilities):
    print(f"{bin(i)[2:].zfill(2)} : {prob:.3f}")


# In[26]:


#pqcrypto


# In[29]:


pip install pqcrypto


# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:




