async function load(flag: string): Promise<any> {
  return import(flag);
}
process.env.SECRET_KEY;