dict = {'k1':'v1', 'k2':'v2'}

name_components = [s for s in dict.itervalues() if s]

print ':'.join(name_components)

