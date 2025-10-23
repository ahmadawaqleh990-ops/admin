<?php
// admin/dashboard.php (add inline "approve + redirect" per visitor strip)
// PHP 7+
declare(strict_types=1);

// حمّل ووردبريس
$wp_load_guess = __DIR__ . '/../wp-load.php';
if (!file_exists($wp_load_guess)) {
  // جرّب مسار بديل إن لزم (يمكنك تبديله لمسارك الصحيح)
  $wp_load_guess = dirname(__DIR__) . '/wp-load.php';
}
require_once $wp_load_guess;

global $wpdb;

/* =====================[ Helpers ]===================== */
if (session_status() !== PHP_SESSION_ACTIVE) session_start();
function e($v){ return htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'); }
function flash_set($key,$val){ $_SESSION['__flash'][$key]=$val; }
function flash($key){ $v=$_SESSION['__flash'][$key]??null; unset($_SESSION['__flash'][$key]); return $v; }
function csrf_token(){ if (empty($_SESSION['__csrf'])) $_SESSION['__csrf']=bin2hex(random_bytes(16)); return $_SESSION['__csrf']; }
function check_csrf($t){ return isset($_SESSION['__csrf']) && hash_equals($_SESSION['__csrf'], (string)$t); }

$table = $wpdb->prefix . 'approvals';
$ADMIN_PASS = 'change-me'; // غيّرها فورًا

/* =====================[ Utilities ]===================== */
function table_exists_wp(string $name): bool {
  global $wpdb;
  $sql = $wpdb->prepare("SHOW TABLES LIKE %s", $name);
  return (bool)$wpdb->get_var($sql);
}
function ensure_online_table(): string {
  global $wpdb;
  $tbl = $wpdb->prefix . 'visitor_online';
  if (!table_exists_wp($tbl)) {
    $charset = $wpdb->get_charset_collate();
    // إنشاء بسيط؛ لو لم تكن لديك صلاحية CREATE TABLE لن يتوقف التنفيذ
    $wpdb->query("CREATE TABLE IF NOT EXISTS `{$tbl}` (
      `visitor_id` varchar(128) NOT NULL,
      `last_seen`  datetime NOT NULL,
      `ip`         varchar(64) NULL,
      `ua`         varchar(255) NULL,
      PRIMARY KEY (`visitor_id`),
      KEY `last_seen` (`last_seen`)
    ) {$charset}");
  }
  return $tbl;
}
function is_visitor_online(string $visitor_id, int $thresholdSecs=120): bool {
  global $wpdb;
  if ($visitor_id==='') return false;
  $tbl = ensure_online_table();
  $since = gmdate('Y-m-d H:i:s', time()-$thresholdSecs);
  $c = (int)$wpdb->get_var($wpdb->prepare(
    "SELECT COUNT(*) FROM `{$tbl}` WHERE visitor_id=%s AND last_seen >= %s",
    $visitor_id, $since
  ));
  return $c>0;
}
function host_path_from_url(string $url): string {
  $p = @parse_url($url);
  return ($p['host'] ?? '') . ($p['path'] ?? '');
}
function page_title_from_url(string $url): string {
  $post_id = url_to_postid($url);
  return $post_id ? (string)get_the_title($post_id) : '';
}
function get_submission_keys(int $submission_id, array $keys): array {
  global $wpdb;
  $tbl_vals = $wpdb->prefix . 'e_submissions_values';
  if (!table_exists_wp($tbl_vals) || !$submission_id || !$keys) return [];
  $in = implode(',', array_fill(0, count($keys), '%s'));
  $rows = $wpdb->get_results($wpdb->prepare(
    "SELECT `key`,`value` FROM {$tbl_vals} WHERE submission_id=%d AND `key` IN ($in)",
    ...array_merge([$submission_id], $keys)
  ), ARRAY_A);
  $out = [];
  foreach($rows as $r){ $out[$r['key']] = (string)$r['value']; }
  return $out;
}
function infer_visitor_name_from_submission(int $submission_id): string {
  $candidates = [
    'name','your-name','fullname','full_name','full-name','الاسم','الإسم',
    'first_name','first-name','firstName','الاسم_الاول','الاسم-الاول',
    'last_name','last-name','lastName','اسم_العائلة','اسم-العائلة'
  ];
  $vals = get_submission_keys($submission_id, $candidates);
  $first=''; $last='';
  foreach(['name','your-name','fullname','full_name','full-name','الاسم','الإسم'] as $k){ if (!empty($vals[$k])) return trim($vals[$k]); }
  foreach(['first_name','first-name','firstName','الاسم_الاول','الاسم-الاول'] as $k){ if (!empty($vals[$k])) { $first = trim($vals[$k]); break; } }
  foreach(['last_name','last-name','lastName','اسم_العائلة','اسم-العائلة'] as $k){ if (!empty($vals[$k])) { $last = trim($vals[$k]); break; } }
  return trim($first . ' ' . $last);
}
function fetch_submission_fields_via_context(array $approval_row, ?int $window_minutes = null): array {
  global $wpdb;
  $win_qs  = isset($_GET['win']) ? max(1, (int)$_GET['win']) : null;
  $window  = $window_minutes !== null ? $window_minutes : ($win_qs ?: 15);

  $tbl_sub  = $wpdb->prefix . 'e_submissions';
  $tbl_vals = $wpdb->prefix . 'e_submissions_values';
  if (!table_exists_wp($tbl_sub) || !table_exists_wp($tbl_vals)) return [];

  $redir      = trim((string)($approval_row['redirect_url'] ?? ''));
  $created_at = trim((string)($approval_row['created_at'] ?? ''));
  $centerTs   = $created_at !== '' ? strtotime($created_at) : time();

  $from = gmdate('Y-m-d H:i:s', $centerTs - ($window * 60));
  $to   = gmdate('Y-m-d H:i:s', $centerTs);

  $needle = $redir !== '' ? host_path_from_url($redir) : '';
  $like   = $needle !== '' ? ('%' . $wpdb->esc_like($needle) . '%') : '';
  $urlKeys = ['page_url','referrer','current_url','source_url'];
  $inUrl   = implode(',', array_fill(0, count($urlKeys), '%s'));

  $take_one = function(int $id) use ($tbl_vals): array {
    global $wpdb;
    $rows = $wpdb->get_results($wpdb->prepare("SELECT `key`,`value` FROM {$tbl_vals} WHERE submission_id=%d", $id), ARRAY_A);
    $fields = [];
    foreach ($rows as $r) {
      $k = (string)$r['key']; $v = (string)$r['value'];
      if (in_array($k, ['page_id','_wpnonce'], true)) continue;
      $fields[$k] = isset($fields[$k]) ? ($fields[$k] . "\n" . $v) : $v;
    }
    return $fields + ['__submission_id' => $id];
  };

  if ($needle !== '') {
    $id = $wpdb->get_var($wpdb->prepare(
      "SELECT s.id FROM {$tbl_sub} s JOIN {$tbl_vals} v ON v.submission_id = s.id
       WHERE v.`key` IN ($inUrl) AND v.`value` LIKE %s
         AND s.created_at BETWEEN %s AND %s
       ORDER BY s.created_at DESC LIMIT 1",
      ...array_merge($urlKeys, [$like, $from, $to])
    )); if ($id) return $take_one((int)$id);
    $id = $wpdb->get_var($wpdb->prepare(
      "SELECT s.id FROM {$tbl_sub} s
       WHERE s.source LIKE %s AND s.created_at BETWEEN %s AND %s
       ORDER BY s.created_at DESC LIMIT 1", $like, $from, $to
    )); if ($id) return $take_one((int)$id);
    $id = $wpdb->get_var($wpdb->prepare(
      "SELECT s.id FROM {$tbl_sub} s JOIN {$tbl_vals} v ON v.submission_id = s.id
       WHERE v.`key` IN ($inUrl) AND v.`value` LIKE %s
         AND s.created_at <= %s
       ORDER BY s.created_at DESC LIMIT 1",
      ...array_merge($urlKeys, [$like, $to])
    )); if ($id) return $take_one((int)$id);
    $id = (int)$wpdb->get_var($wpdb->prepare(
      "SELECT s.id FROM {$tbl_sub} s
       WHERE s.source LIKE %s AND s.created_at <= %s
       ORDER BY s.created_at DESC LIMIT 1", $like, $to
    )); if ($id) return $take_one((int)$id);
  }
  $id = (int)$wpdb->get_var($wpdb->prepare(
    "SELECT s.id FROM {$tbl_sub} s
     WHERE s.created_at <= %s
     ORDER BY s.created_at DESC LIMIT 1", $to
  ));
  return $id ? $take_one((int)$id) : [];
}
function canonical_visitor_id(array $approval_row): string {
  $raw = trim((string)($approval_row['visitor_id'] ?? ''));
  if ($raw !== '' && preg_match('~^VID-[A-Za-z0-9\-]+$~', $raw)) return $raw;
  $fields = fetch_submission_fields_via_context($approval_row, null);
  if ($fields) {
    $candidates = ['visitor_id','Visitor ID','visitorid','vid','fieldidvisitor_id','field_visitor_id','field_5196d27'];
    foreach ($candidates as $k) {
      if (!empty($fields[$k])) {
        $val = trim((string)$fields[$k]);
        $val = strtok($val, "\n\r");
        if ($val !== '' && preg_match('~^VID-[A-Za-z0-9\-]+$~', $val)) return $val;
      }
    }
  }
  if ($raw !== '' && preg_match('~^(field|visitor)(_)?id~i', $raw)) $raw = '';
  return $raw !== '' ? $raw : 'anonymous';
}

/* ===== صفحات ووردبريس ===== */
function list_wp_pages(): array {
  $pages = get_pages(['sort_column' => 'post_title', 'sort_order' => 'asc']);
  $out = [];
  foreach ($pages as $p) {
    $out[] = ['ID'=>(int)$p->ID, 'title'=> get_the_title($p->ID) ?: '(بدون عنوان)', 'url'=> get_permalink($p->ID)];
  }
  return $out;
}

/* =====================[ Auth Flow ]===================== */
if (isset($_GET['logout'])) { unset($_SESSION['logged_in']); flash_set('ok','تم تسجيل الخروج'); header('Location: dashboard.php'); exit; }
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && ($_POST['do'] ?? '') === 'login') {
  if (!check_csrf($_POST['csrf'] ?? '')) { flash_set('err','انتهت صلاحية الجلسة'); header('Location: dashboard.php'); exit; }
  $pass = (string)($_POST['password'] ?? '');
  if (hash_equals($ADMIN_PASS, $pass)) { $_SESSION['logged_in']=true; flash_set('ok','تم تسجيل الدخول'); header('Location: dashboard.php'); exit; }
  flash_set('err','بيانات الدخول غير صحيحة'); header('Location: dashboard.php'); exit;
}
$token = csrf_token();
if (empty($_SESSION['logged_in'])):
  $flash_ok=flash('ok'); $flash_err=flash('err'); ?>
<!DOCTYPE html><html lang="ar" dir="rtl"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>تسجيل الدخول - لوحة الإدارة</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/normalize/8.0.1/normalize.min.css">
<style>
:root{--bg:#0f172a;--card:#111827;--ring:#1f2937;--brand:#7c3aed;--txt:#e5e7eb}
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,"Noto Sans Arabic",Tahoma,Arial,sans-serif;background:var(--bg);color:var(--txt)}
.wrap{max-width:420px;margin:60px auto;padding:0 12px}.card{background:var(--card);border:1px solid var(--ring);border-radius:14px;box-shadow:0 10px 24px rgba(0,0,0,.35);padding:20px}
h1{margin:0 0 14px;font-size:22px}label{display:block;margin:10px 0 6px}
input{width:100%;padding:10px;border:1px solid var(--ring);border-radius:10px;background:#0b1220;color:#e5e7eb}
.btn{width:100%;margin-top:12px;padding:12px;border-radius:10px;border:1px solid var(--brand);background:#7c3aed;color:#fff;font-weight:700;cursor:pointer}
.alert{padding:10px;border-radius:10px;margin:8px 0}.alert.ok{background:#064e3b;border:1px solid #10b981}.alert.err{background:#7f1d1d;border:1px solid #ef4444}
.hint{font-size:12px;color:#9ca3af;margin-top:8px}
</style></head><body>
<div class="wrap"><div class="card"><h1>تسجيل الدخول</h1>
<?php if($flash_ok): ?><div class="alert ok"><?php echo e($flash_ok); ?></div><?php endif; ?>
<?php if($flash_err): ?><div class="alert err"><?php echo e($flash_err); ?></div><?php endif; ?>
<form method="post" action="dashboard.php" autocomplete="off">
  <input type="hidden" name="csrf" value="<?php echo e($token); ?>">
  <input type="hidden" name="do" value="login">
  <label>كلمة المرور</label>
  <input type="password" name="password" required>
  <button class="btn" type="submit">دخول</button>
  <div class="hint">ADMIN_PASS الافتراضي: <strong>change-me</strong> — غيّره داخل الملف.</div>
</form></div></div></body></html>
<?php exit; endif;

/* =====================[ Actions (Delete + Manual Approve/Redirect) ]===================== */
function redirect_with_kept_filters(array $extra = []){
  $keep = $_GET; unset($keep['do'],$keep['id'],$keep['csrf'],$keep['visitor'],$keep['page_id']);
  $q = array_merge($keep, $extra);
  $qs = $q ? ('?' . http_build_query($q)) : '';
  header('Location: dashboard.php' . $qs); exit;
}
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
  $do = $_POST['do'] ?? '';

  // حذف واحد
  if ($do === 'delete_one') {
    if (!check_csrf($_POST['csrf'] ?? '')) { flash_set('err','انتهت صلاحية الجلسة، أعد المحاولة.'); redirect_with_kept_filters(); }
    $id = (int)($_POST['id'] ?? 0);
    if ($id > 0) {
      $deleted = $wpdb->delete($table, ['id' => $id], ['%d']);
      flash_set($deleted? 'ok':'err', $deleted? "تم حذف السجل #{$id} بنجاح.":"تعذّر حذف السجل #{$id}.");
    } else {
      flash_set('err','معرّف غير صالح للحذف.');
    }
    redirect_with_kept_filters();
  }

  // حذف الكل
  if ($do === 'delete_all') {
    if (!check_csrf($_POST['csrf'] ?? '')) { flash_set('err','انتهت صلاحية الجلسة، أعد المحاولة.'); redirect_with_kept_filters(); }
    $_SESSION['__bulk_delete'] = true; redirect_with_kept_filters();
  }

  // موافقة + إعادة توجيه من الشريط
  if ($do === 'manual_redirect') {
    if (!check_csrf($_POST['csrf'] ?? '')) { flash_set('err','انتهت صلاحية الجلسة.'); redirect_with_kept_filters(); }
    $visitor  = trim((string)($_POST['visitor'] ?? ''));
    $page_id  = (int)($_POST['page_id'] ?? 0);

    if ($visitor === '' || $visitor === 'anonymous') { flash_set('err','Visitor ID غير صالح.'); redirect_with_kept_filters(); }
    $target_url = $page_id > 0 ? get_permalink($page_id) : '';
    if ($target_url === '' || !filter_var($target_url, FILTER_VALIDATE_URL)) { flash_set('err','اختر صفحة صالحة لإعادة التوجيه.'); redirect_with_kept_filters(); }

    // أحدث سجل مطابق لهذا الزائر بالضبط (كما هو مخزّن في الأعمدة)
    $last_id = (int)$wpdb->get_var($wpdb->prepare(
      "SELECT id FROM `{$table}` WHERE visitor_id=%s ORDER BY id DESC LIMIT 1", $visitor
    ));
    if ($last_id <= 0) { flash_set('err','لا يوجد سجل مطابق لهذا الزائر.'); redirect_with_kept_filters(); }

    $updated = $wpdb->update(
      $table,
      ['status'=>'approved','redirect_url'=>$target_url,'updated_at'=>current_time('mysql', true)],
      ['id'=>$last_id],
      ['%s','%s','%s'],
      ['%d']
    );
    if ($updated !== false) flash_set('ok', "تم اعتماد السجل #{$last_id} وتعيين إعادة التوجيه.");
    else flash_set('err','تعذّر التحديث.');
    redirect_with_kept_filters();
  }
}

/* =====================[ Data / Filters ]===================== */
$status      = isset($_GET['status']) && in_array($_GET['status'], ['pending','approved','rejected'], true) ? $_GET['status'] : null;
$visitor_id  = isset($_GET['visitor_id']) ? trim((string)$_GET['visitor_id']) : '';

$where = []; $args = [];
if ($status)         { $where[]="status=%s";      $args[]=$status; }
if ($visitor_id!==''){ $where[]="visitor_id=%s";  $args[]=$visitor_id; }

$sql = "SELECT * FROM `{$table}`";
if ($where) $sql .= " WHERE " . implode(' AND ', $where);
$sql .= " ORDER BY id DESC LIMIT 400";
$rows = $args ? $wpdb->get_results($wpdb->prepare($sql, ...$args), ARRAY_A) : $wpdb->get_results($sql, ARRAY_A);

/* حذف الكل عند الطلب */
if (!empty($_SESSION['__bulk_delete'])) {
  unset($_SESSION['__bulk_delete']);
  $ids_to_delete = array_map(function($r){ return (int)$r['id']; }, $rows ?: []);
  if ($ids_to_delete) {
    $ids_sql = implode(',', array_map('intval',$ids_to_delete));
    $ok = $wpdb->query("DELETE FROM `{$table}` WHERE id IN ($ids_sql)");
    flash_set($ok!==false?'ok':'err', $ok!==false? 'تم حذف جميع السجلات المعروضة بنجاح.':'تعذّر حذف السجلات.');
  } else flash_set('ok','لا توجد سجلات مطابقة للحذف.');
  redirect_with_kept_filters();
}

$last_id = !empty($rows) ? (int)$rows[0]['id'] : 0;

/* =====================[ AJAX endpoints ]===================== */
/* Ping (للواجهة الأمامية) */
if (isset($_GET['ajax']) && $_GET['ajax']==='ping') {
  $vid = isset($_GET['visitor_id']) ? trim((string)$_GET['visitor_id']) : '';
  if ($vid!=='') {
    $tbl = ensure_online_table();
    $now = current_time('mysql', true);
    $ip  = $_SERVER['REMOTE_ADDR'] ?? '';
    $ua  = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 250);
    $wpdb->query($wpdb->prepare(
      "INSERT INTO `{$tbl}` (visitor_id,last_seen,ip,ua) VALUES (%s,%s,%s,%s)
       ON DUPLICATE KEY UPDATE last_seen=VALUES(last_seen),ip=VALUES(ip),ua=VALUES(ua)",
      $vid,$now,$ip,$ua
    ));
  }
  header('Content-Type: application/json; charset=UTF-8'); echo json_encode(['ok'=>true], JSON_UNESCAPED_UNICODE); exit;
}

/* Online count (لوحة التحكم) */
if (isset($_GET['ajax']) && $_GET['ajax']==='online_count') {
  if (empty($_SESSION['logged_in'])) { http_response_code(403); echo json_encode(['err'=>'forbidden']); exit; }
  header('Content-Type: application/json; charset=UTF-8');
  $tbl = ensure_online_table();
  $since = gmdate('Y-m-d H:i:s', time()-120);
  $online = (int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM `{$tbl}` WHERE last_seen >= %s", $since));
  $since10 = gmdate('Y-m-d H:i:s', time()-600);
  $fallback = (int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(DISTINCT visitor_id) FROM `{$table}` WHERE created_at >= %s AND visitor_id<>''", $since10));
  echo json_encode(['online'=>$online,'fallback'=>$fallback], JSON_UNESCAPED_UNICODE); exit;
}

/* نافذة منبثقة: كل تسجيلات الزائر (مع استبعاد anonymous) */
if (isset($_GET['ajax']) && $_GET['ajax']==='visitor_log') {
  if (empty($_SESSION['logged_in'])) { http_response_code(403); exit('Forbidden'); }
  $vid = isset($_GET['visitor_id']) ? trim((string)$_GET['visitor_id']) : '';
  header('Content-Type: text/html; charset=UTF-8');
  if ($vid==='' || $vid==='anonymous'){ echo '<div class="small">لا يمكن عرض سجلات زائر غير معروف.</div>'; exit; }

  $recent = $wpdb->get_results("SELECT * FROM `{$table}` ORDER BY id DESC LIMIT 500", ARRAY_A);
  $rows_v = [];
  foreach ($recent as $row) {
    if (canonical_visitor_id($row) === $vid) $rows_v[] = $row;
  }
  if (!$rows_v){ echo '<div class="small">لا توجد تسجيلات لهذا الزائر.</div>'; exit; }

  $online = is_visitor_online($vid) ? '✅ متصل الآن' : '⛔ غير متصل';
  echo '<div class="small" style="margin-bottom:8px">Visitor: <code>'.e($vid).'</code> — الحالة: <strong>'.$online.'</strong></div>';

  echo '<div class="table-wrap" style="max-height:60vh;overflow:auto;border-radius:12px;border:1px solid #1f2937">';
  echo '<table class="table" dir="rtl" style="width:100%;border-collapse:separate;border-spacing:0">';
  echo '<thead><tr><th style="width:70px">#</th><th>المعلومات</th><th style="width:140px">الحالة</th><th>الصفحة/الرابط</th><th style="width:170px">التاريخ</th></tr></thead>';
  echo '<tbody>';

  foreach ($rows_v as $rv) {
    $fields = fetch_submission_fields_via_context($rv, null);
    $sid = (int)($fields['__submission_id'] ?? 0);
    $page_title = page_title_from_url((string)($rv['redirect_url'] ?? ''));
    $meta = get_submission_keys($sid, ['form_name','page_url','current_url','referrer','source_url']);
    $form_name = $meta['form_name'] ?? '';
    $display_page_title = $page_title ?: page_title_from_url($meta['page_url'] ?? ($meta['current_url'] ?? ''));
    $visitor_name = $sid ? infer_visitor_name_from_submission($sid) : '';
    if ($visitor_name==='') $visitor_name = '—';

    echo '<tr>';
    echo '<td>#'.(int)$rv['id'].'</td>';
    echo '<td>';
      echo '<div class="small" style="margin-bottom:6px"><b>اسم الزائر:</b> '.e($visitor_name).'</div>';
      if ($form_name!=='') echo '<div class="small" style="margin-bottom:6px"><b>اسم النموذج:</b> '.e($form_name).'</div>';
      if (!empty($fields)) {
        echo '<div class="values" style="display:flex;flex-wrap:wrap;gap:6px">';
        foreach ($fields as $k=>$v) {
          if (in_array($k,['__submission_id','page_id','page_url','current_url','referrer','source_url','_wpnonce','form_name'], true)) continue;
          echo '<div class="chip" style="background:#0b1220;border:1px solid #1f2937;border-radius:999px;padding:6px 10px;font-size:13px"><b>'.e($k).':</b>&nbsp;<span>'.nl2br(e($v)).'</span></div>';
        }
        echo '</div>';
      } else {
        echo '<div class="small">— لا توجد حقول مطابقة.</div>';
      }
    echo '</td>';
    echo '<td><span class="badge '.e($rv['status']).'">'.e($rv['status']==='pending'?'قيد المراجعة':($rv['status']==='approved'?'مقبول':'مرفوض')).'</span></td>';
    echo '<td>';
      $final_url = $rv['redirect_url'] ?: ($meta['page_url'] ?? $meta['current_url'] ?? $meta['referrer'] ?? $meta['source_url'] ?? '');
      if ($final_url!=='') {
        echo '<a class="link" href="'.e($final_url).'" target="_blank" rel="noopener">فتح</a>';
        if ($display_page_title) echo '<div class="small">الصفحة: '.e($display_page_title).'</div>';
        echo '<div class="small">'.e($final_url).'</div>';
      } else {
        echo '<span class="small">—</span>';
      }
    echo '</td>';
    echo '<td>'.e($rv['created_at'] ?? '').'</td>';
    echo '</tr>';
  }
  echo '</tbody></table></div>';
  exit;
}

/* ====== تجميع لكل الزوار مع استبعاد anonymous ====== */
$grouped = [];
foreach ($rows as $r) {
  $vid = canonical_visitor_id($r);
  if ($vid === 'anonymous') continue; // <-- المطلوب
  $grouped[$vid][] = $r;
}

$pages = list_wp_pages(); // لاستخدامها في القوائم المنسدلة
$flash_ok=flash('ok'); $flash_err=flash('err');
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>لوحة التحكم</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/normalize/8.0.1/normalize.min.css">
<style>
:root{--bg:#0b1120;--card:#0a0f1f;--ring:#1f2937;--ok:#10b981;--bad:#ef4444;--txt:#e5e7eb;--muted:#94a3b8}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,"Noto Sans Arabic",Tahoma,Arial,sans-serif;background:var(--bg);color:var(--txt)}
.wrap{max-width:1280px;margin:18px auto;padding:0 12px}
.header{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
h1{margin:0;font-size:24px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.btn{display:inline-flex;align-items:center;gap:8px;padding:10px 14px;border-radius:12px;border:1px solid var(--ring);
  background:#0f172a;text-decoration:none;color:#e5e7eb;font-weight:700;cursor:pointer}
.btn.bad{background:#7f1d1d;border-color:#7f1d1d}
.card{background:linear-gradient(180deg, rgba(255,255,255,.02), transparent 20%) ,var(--card);border:1px solid var(--ring);
  border-radius:18px;box-shadow:0 10px 24px rgba(0,0,0,.35), inset 0 1px 0 rgba(255,255,255,.03);padding:14px;margin:12px 0}
.tile{background:#0f172a;border:1px solid var(--ring);border-radius:14px;padding:12px 16px;min-width:190px}
.num{font-size:28px;font-weight:800}
.small{font-size:12px;color:#9ca3b8}
.badge{padding:3px 9px;border-radius:999px;font-size:12px;font-weight:800}
.approved{background:#10b981;color:#083344}.rejected{background:#ef4444;color:#111827}
.alert{padding:10px;border-radius:10px;margin:8px 0}
.alert.ok{background:#064e3b;border:1px solid #10b981}.alert.err{background:#7f1d1d;border:1px solid #ef4444}

/* ======== شرائط الزوار ======== */
.visitor-strip{border:2px solid #ffffff;border-radius:14px;padding:10px;display:flex;flex-direction:column;gap:8px;background:#0b1220}
.strip-head{display:flex;align-items:center;gap:10px;justify-content:space-between}
.head-left{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.head-actions{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
select, .mini-input{padding:6px 8px;border:1px solid #1f2937;border-radius:10px;background:#0b1220;color:#e5e7eb;font-size:12px}
.mini-btn{padding:7px 10px;border-radius:10px;border:1px solid var(--ring);background:#0f172a;color:#e5e7eb;font-weight:700;cursor:pointer;font-size:12px}
.mini-btn.ok{background:#065f46;border-color:#065f46}
.entries{display:flex;gap:8px;overflow-x:auto;padding-bottom:4px}
.pill{display:inline-flex;gap:6px;align-items:center;background:#111827;border:1px solid #1f2937;border-radius:999px;padding:6px 10px;font-size:12px;white-space:nowrap}
.pill .pill-id{font-weight:800}
.pill .pill-name{opacity:.9}
.pill .pill-time{opacity:.7}
.strips-grid{display:flex;flex-direction:column;gap:12px}
.kpi{display:flex;gap:12px;flex-wrap:wrap;margin:8px 0}
.sticky-bar{position:sticky;top:8px;z-index:5}
</style>
</head>
<body>
<div class="wrap" id="app" data-status="<?php echo e($status?:''); ?>" data-visitor="<?php echo e($visitor_id); ?>">

  <div class="header">
    <h1>لوحة التحكم</h1>
    <div class="toolbar sticky-bar">
      <form method="get" class="form-inline" action="dashboard.php" style="display:flex;gap:6px;align-items:center">
        <?php if($status): ?><input type="hidden" name="status" value="<?php echo e($status); ?>"><?php endif; ?>
        <label for="visitor_id">فلترة بالزائر:</label>
        <input id="visitor_id" name="visitor_id" type="text" placeholder="Visitor ID" value="<?php echo e($visitor_id); ?>" style="padding:9px 10px;border:1px solid #1f2937;border-radius:10px;background:#0b1220;color:#e5e7eb" />
        <button class="btn" type="submit">تطبيق</button>
        <?php if($visitor_id!==''): ?>
          <a class="btn" href="?<?php $keep=$_GET; unset($keep['visitor_id']); echo http_build_query($keep); ?>">مسح الفلتر</a>
        <?php endif; ?>
      </form>

      <form method="post" onsubmit="return confirm('سيتم حذف جميع السجلات المعروضة. تأكيد؟');">
        <input type="hidden" name="csrf" value="<?php echo e($token); ?>">
        <input type="hidden" name="do" value="delete_all">
        <button class="btn bad" type="submit">🗑️ حذف الكل</button>
      </form>

      <a class="btn" href="?logout=1" onclick="return confirm('تأكيد تسجيل الخروج؟');">تسجيل الخروج</a>
    </div>
  </div>

  <?php if($flash_ok): ?><div class="alert ok"><?php echo e($flash_ok); ?></div><?php endif; ?>
  <?php if($flash_err): ?><div class="alert err"><?php echo e($flash_err); ?></div><?php endif; ?>

  <div class="kpi">
    <div class="tile"><div class="small">آخر ID محمّل</div><div class="num" id="last-id"><?php echo (int)$last_id; ?></div></div>
    <div class="tile"><div class="small">عدد الزوار المعروضين</div><div class="num" id="shown-count"><?php echo count($grouped); ?></div></div>
    <div class="tile"><div class="small">المتصلون الآن</div><div class="num" id="online-now">—</div><div class="small" id="online-fallback" style="margin-top:2px;color:#94a3b8"></div></div>
  </div>

  <!-- ====== الشرائط (anonymous مستبعد) ====== -->
  <div id="visitorStrips" class="strips-grid">
    <?php foreach($grouped as $vid=>$entries): 
      $isOnline = is_visitor_online($vid);
    ?>
    <div class="visitor-strip" data-visitor="<?php echo e($vid); ?>">
      <div class="strip-head">
        <div class="head-left">
          <div><b>Visitor:</b> <code><?php echo e($vid); ?></code></div>
          <span class="badge <?php echo $isOnline?'approved':'rejected'; ?>"><?php echo $isOnline?'متصل الآن':'غير متصل'; ?></span>
        </div>

        <!-- زر موافقة + توجيه مع قائمة الصفحات -->
        <div class="head-actions">
          <form method="post" onsubmit="return confirm('سيتم اعتماد أحدث سجل لهذا الزائر وتعيين إعادة التوجيه. متابعة؟');" style="display:flex;gap:6px;align-items:center">
            <input type="hidden" name="csrf" value="<?php echo e($token); ?>">
            <input type="hidden" name="do" value="manual_redirect">
            <input type="hidden" name="visitor" value="<?php echo e($vid); ?>">
            <select name="page_id" required>
              <option value="">— اختر صفحة —</option>
              <?php foreach($pages as $pg): ?>
                <option value="<?php echo (int)$pg['ID']; ?>"><?php echo e($pg['title']); ?></option>
              <?php endforeach; ?>
            </select>
            <button class="mini-btn ok" type="submit">✅ موافقة + توجيه</button>
          </form>

          <!-- فتح التفاصيل (اختياري) -->
          <a href="#" class="mini-btn view-all" data-visitor="<?php echo e($vid); ?>">عرض التفاصيل</a>
        </div>
      </div>

      <div class="entries">
        <?php
          foreach($entries as $r){
            $fields = fetch_submission_fields_via_context($r, null);
            $sid = (int)($fields['__submission_id'] ?? 0);
            $meta = $sid ? get_submission_keys($sid, ['form_name']) : [];
            $form_name = $meta['form_name'] ?? 'form';
            echo '<div class="pill" title="#'.(int)$r['id'].' • '.e($form_name).' • '.e($r['created_at']).'">'.
                   '<span class="pill-id">#'.(int)$r['id'].'</span>'.
                   '<span class="pill-name">'.e($form_name).'</span>'.
                   '<span class="pill-time">'.e($r['created_at']).'</span>'.
                 '</div>';
          }
        ?>
      </div>
    </div>
    <?php endforeach; ?>
  </div>

</div>

<!-- Modal -->
<div class="modal-backdrop" id="visitorModal" style="position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:center;justify-content:center;z-index:50">
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="visitorModalTitle" style="width:min(100%, 980px);max-height:80vh;background:#0a0f1f;border:1px solid #1f2937;border-radius:16px;box-shadow:0 20px 40px rgba(0,0,0,.5);display:flex;flex-direction:column">
    <div class="modal-header" style="display:flex;align-items:center;justify-content:space-between;padding:10px 12px;border-bottom:1px solid #1f2937">
      <div class="modal-title" id="visitorModalTitle" style="font-weight:800">سجلات الزائر</div>
      <div class="modal-actions" style="display:flex;gap:8px;align-items:center">
        <a class="mini-btn" id="openAsPage" href="#" target="_blank" rel="noopener">فتح كصفحة</a>
        <button class="mini-btn bad" id="closeModal" type="button">إغلاق</button>
      </div>
    </div>
    <div class="modal-body" id="visitorModalBody" style="padding:12px;overflow:auto"><div class="small">اختر زائرًا لعرض التفاصيل…</div></div>
  </div>
</div>

<script>
(function(){
  var stripsWrap = document.getElementById('visitorStrips');

  // فتح المودال
  var modal = document.getElementById('visitorModal'),
      modalBody = document.getElementById('visitorModalBody'),
      openAsPage = document.getElementById('openAsPage');

  function openModalForVisitor(vid){
    if (vid === 'anonymous') return;
    var pageUrl = new URL(window.location.href);
    pageUrl.searchParams.set('view','visitor');
    pageUrl.searchParams.set('visitor_id', vid);
    openAsPage.href = pageUrl.toString();

    var url = new URL(window.location.href);
    url.searchParams.set('ajax','visitor_log');
    url.searchParams.set('visitor_id', vid);

    modalBody.innerHTML = '<div class="small">جاري التحميل…</div>';
    modal.style.display = 'flex';
    fetch(url.toString(), {credentials:'same-origin'})
      .then(r => r.text())
      .then(html => { modalBody.innerHTML = html; })
      .catch(() => { modalBody.innerHTML = '<div class="small">تعذّر تحميل السجلات.</div>'; });
  }

  document.addEventListener('click', function(ev){
    var btn = ev.target.closest('.view-all');
    if (btn){
      ev.preventDefault();
      var vid = btn.getAttribute('data-visitor');
      if (vid) openModalForVisitor(vid);
      return;
    }
    var strip = ev.target.closest('.visitor-strip');
    if (strip && !ev.target.closest('.view-all') && (ev.target.tagName !== 'SELECT') && !ev.target.closest('form')){
      openModalForVisitor(strip.getAttribute('data-visitor'));
    }
  });

  document.getElementById('closeModal').addEventListener('click', function(){ modal.style.display='none'; });
  modal.addEventListener('click', function(ev){ if (ev.target === modal) modal.style.display='none'; });
})();
</script>
</body>
</html>
