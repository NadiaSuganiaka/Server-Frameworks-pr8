import { createApp } from './bootstrap';
import { config } from './config';

async function main() {
  const app = await createApp();
  await app.listen(config().port, '127.0.0.1');
}

main().catch(() => {
  console.error('Startup failed. Check database connection and environment configuration.');
  process.exit(1);
});
