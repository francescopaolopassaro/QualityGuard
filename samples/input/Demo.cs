/*
 * Demo utility. TODO: add parameter validation
 */
public static class DemoCalculator
{
	public static int Sum(int a, int b)
    {
        if (a > 0)
        {
            if (b > 0)
            {
                return a + b;
            }
        }

        return 0;
    }

    // FIXME: this allocates too much
    public static int Compute(int x, int y, int z)
    {
        var result = 0;
        for (var i = 0; i < x; i++)
        {
            for (var j = 0; j < y; j++)
            {
                for (var k = 0; k < z; k++)
                {
                    if (i > 0 && j > 0)
                    {
                        result += i * j;
                    }
                }
            }
        }
        return result;
    }

    public static void Unused()
    {
    }
}
