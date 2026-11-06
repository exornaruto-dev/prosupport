const { createClient } = require('@supabase/supabase-js');

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const url = process.env.SUPABASE_URL;
  const anonKey = process.env.SUPABASE_ANON_KEY;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !anonKey || !serviceKey) {
    return res.status(500).json({ error: 'Server is missing Supabase environment variables.' });
  }

  const authHeader = req.headers.authorization || '';
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) return res.status(401).json({ error: 'กรุณาเข้าสู่ระบบใหม่' });

  try {
    const callerClient = createClient(url, anonKey, {
      auth: { persistSession: false, autoRefreshToken: false },
      global: { headers: { Authorization: `Bearer ${match[1]}` } }
    });
    const { data: userData, error: userError } = await callerClient.auth.getUser(match[1]);
    if (userError || !userData.user) return res.status(401).json({ error: 'เซสชันไม่ถูกต้องหรือหมดอายุ' });

    const { data: callerProfile, error: profileError } = await callerClient
      .from('profiles')
      .select('role,is_active')
      .eq('id', userData.user.id)
      .single();
    if (profileError || callerProfile?.role !== 'admin' || callerProfile?.is_active !== true) {
      return res.status(403).json({ error: 'เฉพาะ Admin ที่เปิดใช้งานเท่านั้นจึงสร้างบัญชีพนักงานได้' });
    }

    const body = req.body || {};
    const employeeCode = String(body.employee_code || '').trim();
    const fullName = String(body.full_name || '').trim();
    const password = String(body.password || '');
    if (!employeeCode || !fullName || !password) {
      return res.status(400).json({ error: 'กรุณากรอกรหัสพนักงาน ชื่อ และรหัสผ่านให้ครบ' });
    }
    if (!/^[A-Za-z0-9_-]{2,30}$/.test(employeeCode)) {
      return res.status(400).json({ error: 'รหัสพนักงานใช้ได้เฉพาะ A-Z, a-z, 0-9, _ และ - ความยาว 2–30 ตัว' });
    }
    if (password.length < 8) return res.status(400).json({ error: 'รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร' });

    const adminClient = createClient(url, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false }
    });
    const email = `${employeeCode.toLowerCase()}@prosupport.local`;
    const { data: created, error: createError } = await adminClient.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: {
        employee_code: employeeCode,
        full_name: fullName,
      }
    });
    if (createError) {
      const message = /already|registered|duplicate/i.test(createError.message)
        ? 'รหัสพนักงานนี้มีบัญชีอยู่แล้ว'
        : createError.message;
      return res.status(400).json({ error: message });
    }

    // The on_auth_user_created_profile trigger creates the employee profile.
    // Verify it exists; do not silently report success if the trigger/schema is missing.
    const { data: profile, error: verifyError } = await adminClient
      .from('profiles')
      .select('id,employee_code,full_name,role,is_active')
      .eq('id', created.user.id)
      .maybeSingle();
    if (verifyError || !profile) {
      // Roll back the Auth user if its profile was not created.
      await adminClient.auth.admin.deleteUser(created.user.id);
      return res.status(500).json({ error: 'สร้างบัญชี Auth ได้ แต่ไม่พบโปรไฟล์ใน profiles กรุณาตรวจสอบ Trigger on_auth_user_created_profile' });
    }

    return res.status(201).json({
      message: 'สร้างบัญชีพนักงานเรียบร้อย',
      employee: {
        id: profile.id,
        employee_code: profile.employee_code,
        full_name: profile.full_name,
        role: profile.role,
        is_active: profile.is_active
      }
    });
  } catch (error) {
    console.error('admin-create-user error:', error);
    return res.status(500).json({ error: 'เกิดข้อผิดพลาดภายในระบบ' });
  }
};
