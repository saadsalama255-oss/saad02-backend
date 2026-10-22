import 'dotenv/config';
import bcrypt from 'bcryptjs';
import pg from 'pg';
const {Pool}=pg;
const [username, displayName, password]=process.argv.slice(2);
if(!username||!displayName||!password||password.length<12) {
  console.error('Usage: node create-admin.js <username> <display-name> <password-at-least-12-chars>');
  process.exit(1);
}
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_URL?.includes('localhost')?false:{rejectUnauthorized:false}});
const hash=await bcrypt.hash(password,12);
await pool.query(`INSERT INTO app_users(username,display_name,role,password_hash) VALUES($1,$2,'Admin',$3)
 ON CONFLICT(username) DO UPDATE SET display_name=EXCLUDED.display_name,role='Admin',password_hash=EXCLUDED.password_hash`,
[username,displayName,hash]);
await pool.end();
console.log('Admin created/updated.');
