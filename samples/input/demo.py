def compute(a, b):
    # TODO handle negative values
    result = 0
    if a > 0:
        if b > 0:
            result = a * b
        else:
            result = a
    return result


def helper(x):
    if x:
        return "yes"
    return "no"	
