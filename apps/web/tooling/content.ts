import { fileURLToPath } from 'node:url';
import { generateContent } from './content-lib';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const result = await generateContent(root);
console.log(`Validated ${result.articles} articles in seven languages for Umbra ${result.version}.`);
