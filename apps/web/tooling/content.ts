import { fileURLToPath } from 'node:url';
import { validateProtocolPublication } from './protocol-lib';
import { generateContent } from './content-lib';

const root = fileURLToPath(new URL('../../../', import.meta.url));
await validateProtocolPublication(root);
const result = await generateContent(root);
console.log(`Validated ${result.articles} articles in seven languages for Umbra ${result.version}.`);
