import { investigate } from './investigator';
import { resolveScanProfile } from './profiles';

function argument(name: string): string | undefined {
  const index = Bun.argv.indexOf(`--${name}`);
  return index >= 0 ? Bun.argv[index + 1] : undefined;
}

const hostname = argument('target');
if (!hostname) {
  console.error('Usage: bun run agent:once -- --target example.com [--profile light|standard|extended] [--model glm-5.3:cloud] [--json report.json]');
  process.exit(2);
}

const report = await investigate({ id: hostname, hostname, authorizationStatus: 'admin_override' }, {
  profile: resolveScanProfile(argument('profile')),
  model: argument('model'),
  baseUrl: argument('ollama-url'),
  onAction: (action) => console.error(`[${action.at}] ${action.tool}: ${action.summary.replace(/\s+/g, ' ').slice(0, 180)}`)
});

const output = JSON.stringify(report, null, 2);
const outputPath = argument('json');
if (outputPath) await Bun.write(outputPath, output);
console.log(output);
