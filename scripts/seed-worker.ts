import PocketBase from 'pocketbase';

const baseUrl = process.env['POCKETBASE_URL'] || 'http://127.0.0.1:8090';
const superuserEmail = process.env['POCKETBASE_SUPERUSER_EMAIL'];
const superuserPassword = process.env['POCKETBASE_SUPERUSER_PASSWORD'];
const workerEmail = process.env['POCKETBASE_WORKER_EMAIL'];
const workerPassword = process.env['POCKETBASE_WORKER_PASSWORD'];

if (!superuserEmail || !superuserPassword || !workerEmail || !workerPassword) {
  throw new Error('PocketBase superuser and worker credentials are required to provision the observer identity.');
}
if (workerPassword.length < 16) throw new Error('POCKETBASE_WORKER_PASSWORD must contain at least 16 characters.');

const pb = new PocketBase(baseUrl);
pb.autoCancellation(false);
await pb.collection('_superusers').authWithPassword(superuserEmail, superuserPassword);

let worker;
try {
  worker = await pb.collection('workers').getFirstListItem(pb.filter('email = {:email}', { email: workerEmail }));
  worker = await pb.collection('workers').update(worker.id, {
    password: workerPassword, passwordConfirm: workerPassword, active: true,
    purpose: 'Wellguard bounded reconnaissance worker', verified: true
  });
} catch {
  worker = await pb.collection('workers').create({
    email: workerEmail, password: workerPassword, passwordConfirm: workerPassword,
    active: true, purpose: 'Wellguard bounded reconnaissance worker', verified: true
  });
}

console.log(`Provisioned least-privilege observer ${worker['email']} (${worker.id}).`);
