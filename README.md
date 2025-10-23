<?php
// admin/dashboard.php
declare(strict_types=1);
require_once __DIR__ . '/../wp-load.php';
global $wpdb;

/**
 * مصادر الإرسالات المدعومة:
 * - wp_e_submissions + wp_e_submissions_values (Elementor)
 * - {$wpdb->prefix}approvals (إن وُجد)
 * - submissions / wp_submissions (إن وُجد)
 *
 * الإضافات الجديدة:
 * - action=delete_visitor (POST): حذف كل إرسالات زائر محدّد من كل المصادر.
 * - action=delete_all (POST): حذف كل الإرسالات من كل المصادر (تحذير).
 * كلاهما محميّان بـ CSRF token داخل الجلسة.
 */

session_start();
$password = '12345'; // غيّرها فورًا
function esc($v){ return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

// CSRF token
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
}
$CSRF = $_SESSION['csrf'];

// شاشة الدخول
if (!isset($_SESSION['logged_in'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (isset($_POST['pass']) && hash_equals($password, (string)$_POST['pass'])) {
            $_SESSION['logged_in'] = true;
            header("Location: dashboard.php"); exit;
        } else { $error = 'كلمة المرور غير صحيحة'; }
    }
    ?>
    <!doctype html><html lang="ar" dir="rtl"><head>
      <meta charset="utf-8"><title>تسجيل الدخول - لوحة التحكم</title>
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <style>
        body{font-family:system-ui,-apple-system,Segoe UI,Tahoma,Arial;background:#f5f6f7;margin:0;display:grid;place-items:center;min-height:100vh}
        form{background:#fff;padding:24px;border-radius:14px;box-shadow:0 10px 30px rgba(0,0,0,.08);width:min(92vw,360px)}
        h2{margin:0 0 12px} input,button{font:inherit}
        input{padding:10px 12px;width:100%;border:1px solid #e2e8f0;border-radius:10px}
        button{padding:10px 14px;border:0;border-radius:10px;background:#0ea5e9;color:#fff;margin-top:12px;cursor:pointer}
        .err{color:#dc2626;margin-top:8px}
      </style>
    </head><body>
      <form method="post">
        <h2>لوحة التحكم</h2>
        <input type="password" name="pass" placeholder="كلمة المرور" required>
        <button>دخول</button>
        <?php if(!empty($error)) echo "<p class='err'>".esc($error)."</p>"; ?>
      </form>
    </body></html><?php
    exit;
}

// ---------- أدوات عامّة ----------
function table_exists(string $table): bool {
    global $wpdb;
    $like = $wpdb->esc_like($table);
    $t = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $like));
    return $t !== null && $t !== '';
}
function get_columns(string $table): array { global $wpdb; return $wpdb->get_col("DESC `$table`", 0) ?: []; }
function get_created_at(array $row): string {
    foreach (['created_at','created_on','date_added','submitted_at','time','timestamp','date','created'] as $c) {
        if (!empty($row[$c])) return (string)$row[$c];
    }
    return '';
}
function parse_any_to_assoc($raw): array {
    if (!is_string($raw) || $raw==='') return [];
    $t = trim($raw);
    if (($t[0]??'')==='{' || ($t[0]??'')==='[') {
        $j = json_decode($raw, true);
        if (json_last_error()===JSON_ERROR_NONE && is_array($j)) {
            $out=[]; $it=function($p,$v) use (&$out,&$it){ if(is_array($v)){ foreach($v as $k=>$vv){ $it($p===''?(string)$k:($p.'.'.$k),$vv);} } else { if(is_object($v)) $v=json_decode(json_encode($v),true); if(is_array($v)) $v=json_encode($v,JSON_UNESCAPED_UNICODE); $out[$p]=(string)$v; } }; $it('',$j);
            return $out;
        }
    }
    if (preg_match('/^(a|O|s|i|b|d):/', $t)) {
        $u = @maybe_unserialize($raw);
        if (is_array($u)) { $out=[]; foreach($u as $k=>$v){ if(is_array($v)||is_object($v)) $v=json_encode($v,JSON_UNESCAPED_UNICODE); $out[(string)$k]=(string)$v; } return $out; }
    }
    if (strpos($raw,'=')!==false && (strpos($raw,'&')!==false || strpos($raw,'%')!==false)) {
        $arr=[]; parse_str($raw,$arr);
        if ($arr){ $out=[]; foreach($arr as $k=>$v){ if(is_array($v)||is_object($v)) $v=json_encode($v,JSON_UNESCAPED_UNICODE); $out[(string)$k]=(string)$v; } return $out; }
    }
    $lines = preg_split('/\r\n|\r|\n/', $raw);
    if ($lines && count($lines)>1) { $out=[]; foreach($lines as $ln){ if(strpos($ln,':')!==false){ [$k,$v]=array_map('trim',explode(':',$ln,2)); if($k!=='') $out[$k]=$v; } } if($out) return $out; }
    return [];
}
function derive_page_info(array $row): array {
    $label=''; $key='';
    if (!empty($row['page_title'])) $label=(string)$row['page_title'];
    $post_id=0;
    if (!empty($row['post_id']) && ctype_digit((string)$row['post_id'])) $post_id=(int)$row['post_id'];
    else {
        $url=$row['page_url'] ?? ($row['referrer'] ?? '');
        if ($url) { $maybe=url_to_postid($url); if ($maybe) $post_id=(int)$maybe; }
    }
    if ($post_id>0){ $t=get_the_title($post_id); if($t) $label=$label?:$t; $key='post:'.$post_id; }
    else {
        $url=$row['page_url'] ?? ($row['referrer'] ?? '');
        if ($url){ $key='url:'.$url; if(!$label) $label=wp_strip_all_tags($url); }
        elseif ($label){ $key='title:'.$label; }
    }
    if(!$label) $label='صفحة غير معروفة'; if(!$key) $key='unknown';
    return ['page_label'=>$label,'page_key'=>$key];
}
function get_site_pages_options(): array {
    $types=['page','post']; if (post_type_exists('product')) $types[]='product';
    $q=new WP_Query(['post_type'=>$types,'post_status'=>'publish','posts_per_page'=>1000,'orderby'=>'title','order'=>'ASC','no_found_rows'=>true,'fields'=>'ids']);
    $out=[]; if(!empty($q->posts)){ foreach($q->posts as $pid){ $out[]=['key'=>'site:post:'.$pid,'label'=>get_the_title($pid)?:('بدون عنوان #'.$pid),'url'=>get_permalink($pid)]; } }
    return $out;
}

/** ------------- تجميع البيانات من المصادر ------------- **/
function collect_elementor_submissions(?string $filterVisitorId=null, ?string $page_key=''): array {
    global $wpdb;
    $out=[]; $tblS=$wpdb->prefix.'e_submissions'; $tblV=$wpdb->prefix.'e_submissions_values';
    if (!table_exists($tblS) || !table_exists($tblV)) return $out;

    $ids=[];
    if ($filterVisitorId){
        $ids = $wpdb->get_col(
            $wpdb->prepare("SELECT DISTINCT submission_id FROM `$tblV` WHERE value IN (%s,%s,%s) OR value LIKE %s",
                $filterVisitorId, json_encode($filterVisitorId,JSON_UNESCAPED_UNICODE), serialize($filterVisitorId), '%'.$wpdb->esc_like($filterVisitorId).'%'
            )
        ) ?: [];
    } else {
        $ids = $wpdb->get_col("SELECT id FROM `$tblS` ORDER BY id DESC LIMIT 200") ?: [];
    }
    if (!$ids) return $out;

    $idsFiltered = $ids;
    if ($page_key){
        $idsFiltered=[];
        if (strpos($page_key,'post:')===0 || strpos($page_key,'site:post:')===0){
            $pid=(int)preg_replace('~^(site:)?post:~','',$page_key);
            if ($pid>0){ $url=get_permalink($pid);
                $idsFiltered=$wpdb->get_col($wpdb->prepare("SELECT DISTINCT submission_id FROM `$tblV` WHERE (value=%s OR value=%s OR value=%s)", (string)$pid,(string)$url,(string)url_to_postid($url))) ?: [];
                $idsFiltered=array_values(array_intersect($idsFiltered,$ids));
            }
        } elseif (strpos($page_key,'url:')===0){
            $u=substr($page_key,4);
            $idsFiltered=$wpdb->get_col($wpdb->prepare("SELECT DISTINCT submission_id FROM `$tblV` WHERE value=%s", $u)) ?: [];
            $idsFiltered=array_values(array_intersect($idsFiltered,$ids));
        } else { $idsFiltered=$ids; }
    }
    if (!$idsFiltered) return $out;

    $ph=implode(',', array_fill(0,count($idsFiltered),'%d'));
    $valuesRows=$wpdb->get_results($wpdb->prepare("SELECT * FROM `$tblV` WHERE submission_id IN ($ph) ORDER BY id ASC", ...array_map('intval',$idsFiltered)), ARRAY_A) ?: [];
    $bySub=[];
    foreach($valuesRows as $vr){
        $sid=(int)$vr['submission_id']; if(!isset($bySub[$sid])) $bySub[$sid]=[];
        $k=!empty($vr['field_id']) ? 'field_'.$vr['field_id'] : (!empty($vr['key'])?(string)$vr['key']:'value');
        $bySub[$sid][$k]=(string)$vr['value'];
        if (!empty($vr['key'])) $bySub[$sid][$vr['key']]=(string)$vr['value'];
    }
    $headers=$wpdb->get_results($wpdb->prepare("SELECT * FROM `$tblS` WHERE id IN ($ph) ORDER BY id DESC", ...array_map('intval',$idsFiltered)), ARRAY_A) ?: [];

    foreach($headers as $h){
        $sid=(int)$h['id']; $fields=$bySub[$sid] ?? [];
        $visitor_id='';
        foreach(['visitor_id','vid','visitor','_visitor','session_id'] as $cand){ if(!empty($fields[$cand])){ $visitor_id=(string)$fields[$cand]; break; } }
        if(!$visitor_id && $filterVisitorId) $visitor_id=$filterVisitorId;

        $row = [
            'page_title' => $fields['page_title'] ?? '',
            'page_url'   => $fields['page_url'] ?? ($fields['referer'] ?? ''),
            'post_id'    => $fields['post_id'] ?? '',
            'status'     => $h['status'] ?? ($fields['status'] ?? ''),
        ];
        $pi=derive_page_info($row);
        $msg=$h['message'] ?? ($fields['message'] ?? ($fields['msg'] ?? ''));

        $out[]=[
            'source'=>'elementor',
            'id'=>'elementor:'.$sid,
            'visitor_id'=>$visitor_id,
            'status'=>(string)($h['status'] ?? 'pending'),
            'redirect_url'=>'',
            '_created_at'=>get_created_at($h),
            '_page_label'=>$pi['page_label'],
            '_page_key'=>$pi['page_key'],
            '_fields'=>$fields,
            '_message'=>(string)$msg,
            'raw'=>$h,
        ];
    }
    return $out;
}
function collect_approvals(?string $filterVisitorId=null, ?string $page_key=''): array {
    global $wpdb;
    $out=[]; $table=$wpdb->prefix.'approvals';
    if (!table_exists($table)) return $out;
    $cols=get_columns($table);

    $where='WHERE 1=1'; $params=[];
    if ($filterVisitorId){ if(in_array('visitor_id',$cols,true)){ $where.=" AND visitor_id=%s"; $params[]=$filterVisitorId; } else { return $out; } }
    if ($page_key){
        if (strpos($page_key,'site:post:')===0 || strpos($page_key,'post:')===0){
            $pid=(int)preg_replace('~^(site:)?post:~','',$page_key);
            if ($pid>0){
                if (in_array('post_id',$cols,true)){ $where.=" AND post_id=%d"; $params[]=$pid; }
                elseif (in_array('page_url',$cols,true)){ $where.=" AND page_url=%s"; $params[]=get_permalink($pid); }
            }
        } elseif (strpos($page_key,'url:')===0){
            $u=substr($page_key,4);
            if (in_array('page_url',$cols,true)){ $where.=" AND page_url=%s"; $params[]=$u; }
            elseif (in_array('referrer',$cols,true)){ $where.=" AND referrer=%s"; $params[]=$u; }
        } elseif (strpos($page_key,'title:')===0){
            $t=substr($page_key,6);
            if (in_array('page_title',$cols,true)){ $where.=" AND page_title=%s"; $params[]=$t; }
        } elseif ($page_key==='unknown'){
            $cond=[]; foreach(['post_id','page_url','referrer','page_title'] as $c){ if(in_array($c,$cols,true)) $cond[]="($c IS NULL OR $c='')"; }
            if ($cond) $where.=" AND ".implode(' AND ',$cond);
        }
    }
    $sql="SELECT * FROM `$table` $where ORDER BY id DESC LIMIT 1000";
    $rows=$params ? $wpdb->get_results($wpdb->prepare($sql, ...$params), ARRAY_A) : $wpdb->get_results($sql, ARRAY_A);
    foreach($rows as $r){
        $pi=derive_page_info($r);
        $fields=[];
        foreach(['payload','form_data','fields','submission','data','meta'] as $cand){ if(!empty($r[$cand])){ $tmp=parse_any_to_assoc((string)$r[$cand]); if($tmp){ $fields=$tmp; break; } } }
        foreach(get_columns($table) as $c){ if(stripos($c,'field_')===0 && !empty($r[$c])) $fields[$c]=(string)$r[$c]; }
        foreach(['name','email','phone','message'] as $g){ if(!empty($r[$g])) $fields[$g]=(string)$r[$g]; }
        $out[]=[
            'source'=>'approvals','id'=>'approvals:'.$r['id'],
            'visitor_id'=>(string)($r['visitor_id'] ?? ''),'status'=>(string)($r['status'] ?? 'pending'),
            'redirect_url'=>(string)($r['redirect_url'] ?? ''),'_created_at'=>get_created_at($r),
            '_page_label'=>$pi['page_label'],'_page_key'=>$pi['page_key'],
            '_fields'=>$fields,'_message'=>(string)($r['message'] ?? ($fields['message'] ?? '')),
            'raw'=>$r,
        ];
    }
    return $out;
}
function collect_custom_submissions(?string $filterVisitorId=null, ?string $page_key=''): array {
    global $wpdb;
    $out=[];
    foreach(['submissions','wp_submissions'] as $name){
        $table=$name; if($name==='wp_submissions') $table=$wpdb->prefix.'submissions';
        if (!table_exists($table)) continue;
        $cols=get_columns($table);
        $where='WHERE 1=1'; $params=[];
        if ($filterVisitorId){
            if(in_array('visitor_id',$cols,true)){ $where.=" AND visitor_id=%s"; $params[]=$filterVisitorId; }
            else {
                foreach(['payload','data','fields','form_data','meta','body','content'] as $cand){ if(in_array($cand,$cols,true)){ $where.=" AND $cand LIKE %s"; $params[]='%'.$wpdb->esc_like($filterVisitorId).'%'; break; } }
            }
        }
        if ($page_key){
            if (strpos($page_key,'site:post:')===0 || strpos($page_key,'post:')===0){
                $pid=(int)preg_replace('~^(site:)?post:~','',$page_key);
                if ($pid>0){
                    if (in_array('post_id',$cols,true)){ $where.=" AND post_id=%d"; $params[]=$pid; }
                    elseif (in_array('page_url',$cols,true)){ $where.=" AND page_url=%s"; $params[]=get_permalink($pid); }
                }
            } elseif (strpos($page_key,'url:')===0){
                $u=substr($page_key,4); if (in_array('page_url',$cols,true)){ $where.=" AND page_url=%s"; $params[]=$u; }
            } elseif (strpos($page_key,'title:')===0){
                $t=substr($page_key,6); if (in_array('page_title',$cols,true)){ $where.=" AND page_title=%s"; $params[]=$t; }
            }
        }
        $sql="SELECT * FROM `$table` $where ORDER BY id DESC LIMIT 1000";
        $rows=$params ? $wpdb->get_results($wpdb->prepare($sql, ...$params), ARRAY_A) : $wpdb->get_results($sql, ARRAY_A);
        foreach($rows as $r){
            $pi=derive_page_info($r); $fields=[];
            foreach(['payload','data','fields','form_data','meta','body','content'] as $cand){ if(!empty($r[$cand])){ $tmp=parse_any_to_assoc((string)$r[$cand]); if($tmp){ $fields=$tmp; break; } } }
            foreach($cols as $c){ if(stripos($c,'field_')===0 && !empty($r[$c])) $fields[$c]=(string)$r[$c]; }
            foreach(['name','email','phone','message'] as $g){ if(!empty($r[$g])) $fields[$g]=(string)$r[$g]; }
            $out[]=[
                'source'=>$name,'id'=>$name.':'.$r['id'],'visitor_id'=>(string)($r['visitor_id'] ?? ''),
                'status'=>(string)($r['status'] ?? 'pending'),'redirect_url'=>(string)($r['redirect_url'] ?? ''),
                '_created_at'=>get_created_at($r),'_page_label'=>$pi['page_label'],'_page_key'=>$pi['page_key'],
                '_fields'=>$fields,'_message'=>(string)($r['message'] ?? ($fields['message'] ?? '')),'raw'=>$r,
            ];
        }
    }
    return $out;
}
function build_groups_and_pages(?string $filterVisitorId=null): array {
    $all = array_merge(
        collect_elementor_submissions($filterVisitorId, ''),
        collect_approvals($filterVisitorId, ''),
        collect_custom_submissions($filterVisitorId, '')
    );
    foreach($all as &$it){
        if (empty($it['visitor_id'])){
            $f=$it['_fields'] ?? [];
            foreach(['visitor_id','vid','email','phone','mobile','session_id'] as $cand){ if(!empty($f[$cand])){ $it['visitor_id']=(string)$f[$cand]; break; } }
        }
    } unset($it);
    if ($filterVisitorId) $all = array_values(array_filter($all, fn($x)=> (string)$x['visitor_id']===(string)$filterVisitorId));

    $groups=[];
    foreach($all as $item){
        $vid=(string)($item['visitor_id'] ?: 'UNKNOWN');
        if(!isset($groups[$vid])) $groups[$vid]=['items'=>[],'pages'=>[],'last'=>null];
        $groups[$vid]['items'][]=$item;
        $groups[$vid]['last'] = $groups[$vid]['last']
            ? ( ((int)preg_replace('~.*:~','',$groups[$vid]['last']['id']) < (int)preg_replace('~.*:~','',$item['id'])) ? $item : $groups[$vid]['last'] )
            : $item;
        $k=$item['_page_key'] ?? 'unknown'; $l=$item['_page_label'] ?? 'صفحة غير معروفة';
        if(!isset($groups[$vid]['pages'][$k])) $groups[$vid]['pages'][$k]=$l;
    }
    $out=[];
    foreach($groups as $vid=>$g){
        $pages=[]; foreach($g['pages'] as $k=>$l) $pages[]=['key'=>$k,'label'=>$l];
        $last=$g['last'] ?: ['status'=>'pending','id'=>'0'];
        $out[]=[
            'visitor_id'=>$vid,
            'count'=>count($g['items']),
            'last_id'=>(int)preg_replace('~.*:~','',$last['id']),
            'last_status'=>$last['status'] ?? 'pending',
            'redirect_url'=>$last['redirect_url'] ?? '',
            'visitor_pages'=>$pages,
        ];
    }
    usort($out, fn($a,$b)=> $b['last_id'] <=> $a['last_id']); // الأحدث أولاً
    return [$out,$all];
}

/** ------------- إجراءات الحذف (AJAX) ------------- **/
function delete_by_visitor_all_sources(string $visitor_id): array {
    global $wpdb;
    $affected = ['elementor'=>0,'approvals'=>0,'custom'=>0];

    // Elementor
    $tblS=$wpdb->prefix.'e_submissions'; $tblV=$wpdb->prefix.'e_submissions_values';
    if (table_exists($tblS) && table_exists($tblV)){
        $ids = $wpdb->get_col(
            $wpdb->prepare("SELECT DISTINCT submission_id FROM `$tblV` WHERE value IN (%s,%s,%s) OR value LIKE %s",
                $visitor_id, json_encode($visitor_id,JSON_UNESCAPED_UNICODE), serialize($visitor_id), '%'.$wpdb->esc_like($visitor_id).'%'
            )
        ) ?: [];
        if ($ids){
            $ph=implode(',', array_fill(0,count($ids),'%d')); $idsI=array_map('intval',$ids);
            $affV = $wpdb->query($wpdb->prepare("DELETE FROM `$tblV` WHERE submission_id IN ($ph)", ...$idsI));
            $affS = $wpdb->query($wpdb->prepare("DELETE FROM `$tblS` WHERE id IN ($ph)", ...$idsI));
            $affected['elementor'] = (int)($affS ?: 0);
        }
    }
    // approvals
    $appt=$wpdb->prefix.'approvals';
    if (table_exists($appt) && in_array('visitor_id', get_columns($appt), true)){
        $aff = $wpdb->query($wpdb->prepare("DELETE FROM `$appt` WHERE visitor_id=%s", $visitor_id));
        $affected['approvals'] = (int)($aff ?: 0);
    }
    // custom
    foreach(['submissions','wp_submissions'] as $name){
        $table=$name; if($name==='wp_submissions') $table=$wpdb->prefix.'submissions';
        if (!table_exists($table)) continue;
        $cols=get_columns($table);
        if (in_array('visitor_id',$cols,true)){
            $aff=$wpdb->query($wpdb->prepare("DELETE FROM `$table` WHERE visitor_id=%s", $visitor_id));
            $affected['custom'] += (int)($aff ?: 0);
        } else {
            // بحث داخل payload-like ثم حذف باستخدام id
            foreach(['payload','data','fields','form_data','meta','body','content'] as $cand){
                if (in_array($cand,$cols,true)){
                    $ids=$wpdb->get_col($wpdb->prepare("SELECT id FROM `$table` WHERE $cand LIKE %s", '%'.$wpdb->esc_like($visitor_id).'%')) ?: [];
                    if ($ids){ $ph=implode(',', array_fill(0,count($ids),'%d')); $wpdb->query($wpdb->prepare("DELETE FROM `$table` WHERE id IN ($ph)", ...array_map('intval',$ids))); $affected['custom'] += count($ids); }
                    break;
                }
            }
        }
    }

    return $affected;
}
function delete_all_sources(): array {
    global $wpdb;
    $affected = ['elementor'=>0,'approvals'=>0,'custom'=>0];

    // Elementor (احذف الرأس والقيم)
    $tblS=$wpdb->prefix.'e_submissions'; $tblV=$wpdb->prefix.'e_submissions_values';
    if (table_exists($tblS)) { $affS = $wpdb->query("TRUNCATE TABLE `$tblS`"); $affected['elementor'] += (int)($affS!==false ? $wpdb->rows_affected : 0); }
    if (table_exists($tblV)) { $affV = $wpdb->query("TRUNCATE TABLE `$tblV`"); }

    // approvals
    $appt=$wpdb->prefix.'approvals';
    if (table_exists($appt)) { $wpdb->query("TRUNCATE TABLE `$appt`"); }

    // custom
    foreach(['submissions','wp_submissions'] as $name){
        $table=$name; if($name==='wp_submissions') $table=$wpdb->prefix.'submissions';
        if (table_exists($table)) { $wpdb->query("TRUNCATE TABLE `$table`"); }
    }
    return $affected;
}

/** ------------- نهايات AJAX (قائمة/تفاصيل/حذف) ------------- **/
if (isset($_GET['action']) && $_GET['action']==='list') {
    header('Content-Type: application/json; charset=utf-8');
    $filterVid = isset($_GET['vid']) ? (string)$_GET['vid'] : null;
    [$groups,$allItems] = build_groups_and_pages($filterVid);
    echo json_encode([
        'ok'=>true,
        'items'=>$groups,
        'sitePages'=>get_site_pages_options(),
        'max_id'=>array_reduce($groups, fn($m,$i)=>max($m,(int)$i['last_id']), 0),
        'csrf'=>'<?php echo $CSRF; ?>'
    ], JSON_UNESCAPED_UNICODE);
    exit;
}
if (isset($_GET['action']) && $_GET['action']==='details') {
    header('Content-Type: application/json; charset=utf-8');
    $visitor_id = isset($_GET['visitor_id']) ? (string)$_GET['visitor_id'] : '';
    $page_key   = isset($_GET['page']) ? (string)$_GET['page'] : '';
    if ($visitor_id===''){ echo json_encode(['ok'=>false,'error'=>'visitor_id مفقود'], JSON_UNESCAPED_UNICODE); exit; }

    $items = array_merge(
        collect_elementor_submissions($visitor_id, $page_key),
        collect_approvals($visitor_id, $page_key),
        collect_custom_submissions($visitor_id, $page_key)
    );
    if ($page_key){
        $items = array_values(array_filter($items, function($x) use ($page_key){
            if (empty($x['_page_key'])) return $page_key==='unknown';
            if ($page_key==='unknown')  return $x['_page_key']==='unknown';
            return $x['_page_key']===$page_key;
        }));
    }
    usort($items, function($a,$b){
        $ta = strtotime($a['_created_at'] ?? '') ?: 0;
        $tb = strtotime($b['_created_at'] ?? '') ?: 0;
        if ($ta !== $tb) return $tb <=> $ta; // الأحدث أولاً
        return (int)preg_replace('~.*:~','',$b['id']) <=> (int)preg_replace('~.*:~','',$a['id']);
    });

    echo json_encode(['ok'=>true,'visitor_id'=>$visitor_id,'items'=>$items], JSON_UNESCAPED_UNICODE);
    exit;
}
if (isset($_GET['action']) && $_GET['action']==='delete_visitor' && $_SERVER['REQUEST_METHOD']==='POST') {
    header('Content-Type: application/json; charset=utf-8');
    $token = $_POST['csrf'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', (string)$token)) { echo json_encode(['ok'=>false,'error'=>'CSRF']); exit; }
    $visitor_id = isset($_POST['visitor_id']) ? (string)$_POST['visitor_id'] : '';
    if ($visitor_id===''){ echo json_encode(['ok'=>false,'error'=>'visitor_id مفقود']); exit; }

    $aff = delete_by_visitor_all_sources($visitor_id);
    echo json_encode(['ok'=>true,'deleted'=>$aff], JSON_UNESCAPED_UNICODE); exit;
}
if (isset($_GET['action']) && $_GET['action']==='delete_all' && $_SERVER['REQUEST_METHOD']==='POST') {
    header('Content-Type: application/json; charset=utf-8');
    $token = $_POST['csrf'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', (string)$token)) { echo json_encode(['ok'=>false,'error'=>'CSRF']); exit; }
    $confirm = isset($_POST['confirm']) ? (string)$_POST['confirm'] : '';
    if ($confirm!=='YES'){ echo json_encode(['ok'=>false,'error'=>'الرجاء إدخال YES للتأكيد']); exit; }

    $aff = delete_all_sources();
    echo json_encode(['ok'=>true,'deleted'=>$aff], JSON_UNESCAPED_UNICODE); exit;
}

/** ------------------ واجهة المستخدم ------------------ **/
?>
<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>لوحة التحكم</title>
<style>
:root{--bg:#f8fafc;--card:#fff;--muted:#64748b;--ring:#e2e8f0;--ok:#16a34a;--bad:#dc2626;--brand:#0ea5e9}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,Segoe UI,Tahoma,Arial;background:var(--bg);margin:0;color:#0f172a}
.header{display:flex;gap:12px;align-items:center;justify-content:space-between;padding:16px 20px;background:#fff;border-bottom:1px solid var(--ring);position:sticky;top:0;z-index:5}
.header h1{font-size:18px;margin:0}
.container{padding:20px;max-width:1200px;margin-inline:auto}
.grid{display:grid;grid-template-columns:1fr;gap:12px}
@media(min-width:980px){.grid{grid-template-columns:1fr 1fr}}
.bar{display:flex;align-items:center;justify-content:space-between;background:var(--card);border:1px solid var(--ring);border-radius:14px;padding:12px 14px;gap:10px;box-shadow:0 6px 18px rgba(0,0,0,.04);flex-wrap:wrap}
.left{display:flex;align-items:center;gap:8px;min-width:260px;flex:1}
.bar .id{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:360px}
.badge{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;font-size:12px;background:#f1f5f9;color:#0f172a;border:1px solid var(--ring)}
.count{font-weight:700}
.status{padding:4px 10px;border-radius:999px;font-size:12px;border:1px solid var(--ring)}
.status.pending{background:#fffbeb}
.status.approved{background:#ecfdf5;color:#065f46}
.status.rejected{background:#fef2f2;color:#991b1b}
select.page-filter{padding:7px 10px;border:1px solid var(--ring);border-radius:10px;background:#fff;max-width:360px}
.btn{appearance:none;border:0;background:var(--brand);color:#fff;padding:8px 12px;border-radius:10px;cursor:pointer}
.btn.ghost{background:#fff;color:#0f172a;border:1px solid var(--ring)}
.btn.danger{background:#ef4444}
.btn.small{padding:6px 10px;font-size:13px}
.tools{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.hint{color:var(--muted);font-size:12px;margin-top:8px}
.modal{position:fixed;inset:0;background:rgba(2,6,23,.48);display:none;align-items:center;justify-content:center;padding:12px;z-index:20}
.modal.open{display:flex}
.dialog{background:#fff;width:min(96vw,1200px);max-height:86vh;border-radius:16px;overflow:hidden;display:flex;flex-direction:column;border:1px solid var(--ring)}
.dialog header{display:flex;align-items:center;gap:8px;justify-content:space-between;padding:14px 16px;border-bottom:1px solid var(--ring);flex-wrap:wrap}
.dialog h3{margin:0;font-size:16px}
.dialog .content{padding:0;overflow:auto}
.table{width:100%;border-collapse:collapse}
.table th,.table td{padding:10px;border-bottom:1px solid var(--ring);text-align:right;font-size:13px;vertical-align:top}
.table th{background:#f8fafc;position:sticky;top:0;z-index:1}
.kv{display:grid;grid-template-columns:160px 1fr;gap:6px}
.kv div{padding:6px 8px;border:1px solid var(--ring);border-radius:8px;background:#fff}
.kv .k{background:#f8fafc;font-weight:600}
.raw{margin-top:8px}
.raw pre{white-space:pre-wrap;word-break:break-word;background:#f8fafc;border:1px solid var(--ring);border-radius:8px;padding:8px}
.row-actions{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
a.btn-link,a.btn-out{display:inline-flex;align-items:center;gap:6px;padding:7px 10px;border-radius:10px;text-decoration:none;color:#fff}
a.btn-link{background:#0ea5e9}
a.btn-out{background:#ef4444}
.empty{padding:24px;text-align:center;color:#64748b}
.refresh-dot{width:8px;height:8px;border-radius:50%;background:#22c55e;display:inline-block}
.small{font-size:12px;color:#64748b}
.note{font-size:12px;color:#991b1b}
</style>
</head>
<body>
  <div class="header">
    <h1>لوحة التحكم</h1>
    <div class="tools">
      <button class="btn ghost" id="manualRefresh" title="تحديث الآن">تحديث</button>
      <button class="btn danger" id="deleteAllBtn" title="حذف كل الإرسالات">حذف الكل</button>
      <span class="hint"><span class="refresh-dot" id="liveDot"></span> تحديث تلقائي كل 5 ثوانٍ</span>
    </div>
  </div>

  <div class="container">
    <div id="bars" class="grid" aria-live="polite" aria-busy="false"></div>
    <p id="emptyState" class="empty" style="display:none">لا توجد طلبات بعد.</p>
    <p class="note">تنبيه: "حذف الكل" يمسح كل الإرسالات من Elementor والاعتمادات وأي جداول submissions مخصصة.</p>
  </div>

  <div class="modal" id="modal">
    <div class="dialog" role="dialog" aria-modal="true" aria-labelledby="modalTitle">
      <header>
        <h3 id="modalTitle">تفاصيل الزائر</h3>
        <div style="display:flex;gap:8px;align-items:center">
          <label for="modalPageSel">تصفية حسب الصفحة:</label>
          <select id="modalPageSel" class="page-filter"></select>
        </div>
        <button class="btn ghost" id="closeModal">إغلاق</button>
      </header>
      <div class="content">
        <table class="table" id="detailsTable"></table>
      </div>
    </div>
  </div>

<script>
(function(){
  const barsEl = document.getElementById('bars');
  const emptyEl = document.getElementById('emptyState');
  const liveDot = document.getElementById('liveDot');
  const manualBtn = document.getElementById('manualRefresh');
  const deleteAllBtn = document.getElementById('deleteAllBtn');

  const modal = document.getElementById('modal');
  const closeModal = document.getElementById('closeModal');
  const detailsTable = document.getElementById('detailsTable');
  const modalTitle = document.getElementById('modalTitle');
  const modalPageSel = document.getElementById('modalPageSel');

  let latestMaxId = 0;
  let csrf = '';
  const pageSelectionByVisitor = new Map(); // visitor_id -> page_key

  const esc = s => String(s ?? '').replace(/[&<>"']/g, m=>({ '&':'&amp;','<':'&gt;','>':'&lt;','"':'&quot;', "'":'&#039;' }[m]));
  const statusClass = st => (st||'pending').toLowerCase();

  function toast(msg){
    const t=document.createElement('div');
    t.textContent=msg;
    Object.assign(t.style,{position:'fixed',bottom:'16px',left:'50%',transform:'translateX(-50%)',background:'#111827',color:'#fff',padding:'10px 14px',borderRadius:'10px',zIndex:50,boxShadow:'0 10px 30px rgba(0,0,0,.2)'});
    document.body.appendChild(t); setTimeout(()=>{ t.remove(); }, 2200);
  }

  function makePageSelect(visitorPages, sitePages, current){
    const sel = document.createElement('select');
    sel.className = 'page-filter';
    const all = document.createElement('option'); all.value=''; all.textContent='كل الصفحات'; sel.appendChild(all);
    if (visitorPages?.length){
      const og1=document.createElement('optgroup'); og1.label='صفحات الزائر';
      visitorPages.forEach(p=>{ const o=document.createElement('option'); o.value=p.key; o.textContent=p.label; og1.appendChild(o); });
      sel.appendChild(og1);
    }
    if (sitePages?.length){
      const og2=document.createElement('optgroup'); og2.label='كل صفحات الموقع';
      sitePages.forEach(p=>{ const o=document.createElement('option'); o.value=p.key; o.textContent=p.label; og2.appendChild(o); });
      sel.appendChild(og2);
    }
    sel.value = current ?? '';
    return sel;
  }

  function renderBars(items, sitePages){
    barsEl.innerHTML = '';
    if (!items.length){ emptyEl.style.display='block'; barsEl.setAttribute('aria-busy','false'); return; }
    emptyEl.style.display='none';

    items.forEach(it=>{
      const wrap = document.createElement('div'); wrap.className='bar';

      const left = document.createElement('div'); left.className='left';
      left.innerHTML = `
        <div class="id" title="${esc(it.visitor_id)}">👤 ${esc(it.visitor_id)}</div>
        <span class="badge" title="عدد الإرسالات">📝 <span class="count">${it.count}</span></span>
        <span class="status ${statusClass(it.last_status)}" title="آخر حالة">${esc(it.last_status)}</span>
      `;

      const current = pageSelectionByVisitor.get(it.visitor_id) || '';
      const sel = makePageSelect(it.visitor_pages, sitePages, current);
      sel.addEventListener('change', ()=> pageSelectionByVisitor.set(it.visitor_id, sel.value));

      const actions = document.createElement('div'); actions.className='row-actions';
      actions.innerHTML = `
        <button class="btn ghost small" data-vid="${esc(it.visitor_id)}">تفاصيل</button>
        <button class="btn danger small" data-del="${esc(it.visitor_id)}" title="حذف كل تسجيلات هذا الزائر">حذف</button>
      `;
      actions.querySelector('button[data-vid]').addEventListener('click', ()=>{
        const key = pageSelectionByVisitor.get(it.visitor_id) || '';
        openDetails(it.visitor_id, it.visitor_pages || [], sitePages || [], key);
      });
      actions.querySelector('button[data-del]').addEventListener('click', ()=> onDeleteVisitor(it.visitor_id));

      wrap.appendChild(left);
      wrap.appendChild(sel);
      wrap.appendChild(actions);
      barsEl.appendChild(wrap);
    });

    barsEl.setAttribute('aria-busy','false');
  }

  async function fetchList(){
    try{
      barsEl.setAttribute('aria-busy','true');
      const url = 'dashboard.php?action=list'+(location.search.includes('vid=')?('&'+location.search.split('?')[1]):'');
      const res = await fetch(url, {headers:{'Accept':'application/json'}});
      if(!res.ok) throw new Error('network');
      const data = await res.json();
      if(!data.ok) throw new Error('bad');

      if (data.csrf) csrf = data.csrf;

      if (+data.max_id > latestMaxId) { latestMaxId = +data.max_id; liveDot.animate([{opacity:1},{opacity:.2},{opacity:1}],{duration:800}); }

      const saved = new Map(pageSelectionByVisitor);
      (data.items||[]).forEach(it=>{ if (saved.has(it.visitor_id)) pageSelectionByVisitor.set(it.visitor_id, saved.get(it.visitor_id)); });

      renderBars(data.items||[], data.sitePages||[]);
    }catch(e){
      console.error(e); barsEl.setAttribute('aria-busy','false');
    }
  }

  function fillModalPageSelect(visitorPages, sitePages, selected){
    modalPageSel.innerHTML='';
    const all=document.createElement('option'); all.value=''; all.textContent='كل الصفحات'; modalPageSel.appendChild(all);
    if (visitorPages?.length){
      const og1=document.createElement('optgroup'); og1.label='صفحات الزائر';
      visitorPages.forEach(p=>{ const o=document.createElement('option'); o.value=p.key; o.textContent=p.label; og1.appendChild(o); });
      modalPageSel.appendChild(og1);
    }
    if (sitePages?.length){
      const og2=document.createElement('optgroup'); og2.label='كل صفحات الموقع';
      sitePages.forEach(p=>{ const o=document.createElement('option'); o.value=p.key; o.textContent=p.label; og2.appendChild(o); });
      modalPageSel.appendChild(og2);
    }
    modalPageSel.value = selected ?? '';
  }

  async function openDetails(visitor_id, visitorPages=[], sitePages=[], pageKey=''){
    modal.classList.add('open'); document.body.style.overflow='hidden';
    modalTitle.textContent = 'تفاصيل الزائر: ' + visitor_id;
    fillModalPageSelect(visitorPages, sitePages, pageKey);

    const load = async ()=>{
      detailsTable.innerHTML = '<tr><th>المصدر</th><th>المعرّف</th><th>الوقت</th><th>الحالة</th><th>الصفحة</th><th>الحقول/الرسالة</th></tr><tr><td colspan="6">جار التحميل...</td></tr>';
      try{
        const url = new URL('dashboard.php', location.href);
        url.searchParams.set('action','details');
        url.searchParams.set('visitor_id', visitor_id);
        if (modalPageSel.value) url.searchParams.set('page', modalPageSel.value);

        const res = await fetch(url.toString(), {headers:{'Accept':'application/json'}});
        const data = await res.json();
        if(!data.ok) throw new Error('bad');

        if(!data.items || !data.items.length){
          detailsTable.innerHTML = '<tr><th>المصدر</th><th>المعرّف</th><th>الوقت</th><th>الحالة</th><th>الصفحة</th><th>الحقول/الرسالة</th></tr><tr><td colspan="6" class="empty">لا توجد إدخالات.</td></tr>';
          return;
        }

        let html = '<tr><th>المصدر</th><th>المعرّف</th><th>الوقت</th><th>الحالة</th><th>الصفحة</th><th>الحقول/الرسالة</th></tr>';
        data.items.forEach(row=>{
          const src = esc(row.source||'');
          const id = esc(row.id||'');
          const when = esc(row._created_at||'');
          const st = esc((row.status||'pending'));
          const page = esc(row._page_label||'');
          const fields = row._fields || {};
          const msg = row._message || '';

          let kv = '';
          if (fields && Object.keys(fields).length){
            kv += '<div class="kv">';
            Object.keys(fields).forEach(k=>{ kv += '<div class="k">'+esc(k)+'</div><div>'+esc(fields[k])+'</div>'; });
            kv += '</div>';
          }
          if (msg && (!fields || !fields.message)) kv += '<div class="small">الرسالة: '+esc(msg)+'</div>';

          let rawPairs = '';
          if (row.raw){
            rawPairs += '<div class="raw"><details><summary>عرض كل الأعمدة الخام</summary><pre>';
            Object.keys(row.raw).forEach(k=>{ rawPairs += esc(k)+': '+esc(row.raw[k])+"\n"; });
            rawPairs += '</pre></details></div>';
          }

          html += `<tr>
            <td>${src}</td>
            <td>${id}</td>
            <td>${when || '<span class="small">غير متوفر</span>'}</td>
            <td><span class="status ${st.toLowerCase()}">${st}</span></td>
            <td>${page}</td>
            <td>${kv || '<span class="small">لا توجد حقول</span>'}${rawPairs}</td>
          </tr>`;
        });

        detailsTable.innerHTML = html;

      }catch(e){
        console.error(e);
        detailsTable.innerHTML = '<tr><th>المصدر</th><th>المعرّف</th><th>الوقت</th><th>الحالة</th><th>الصفحة</th><th>الحقول/الرسالة</th></tr><tr><td colspan="6" class="empty">حدث خطأ أثناء تحميل التفاصيل.</td></tr>';
      }
    };

    await load();
    modalPageSel.onchange = async ()=>{ await load(); };
  }

  async function onDeleteVisitor(visitor_id){
    if (!csrf){ await fetchList(); }
    const ok = confirm('سيتم حذف جميع تسجيلات هذا الزائر من كل المصادر. هل أنت متأكد؟');
    if (!ok) return;
    try{
      const form = new FormData();
      form.append('csrf', csrf);
      form.append('visitor_id', visitor_id);
      const res = await fetch('dashboard.php?action=delete_visitor', {method:'POST', body:form});
      const data = await res.json();
      if (!data.ok) throw new Error(data.error || 'فشل الحذف');
      toast('تم حذف تسجيلات الزائر بنجاح');
      // أغلق التفاصيل إن كانت مفتوحة على هذا الزائر
      if (modal.classList.contains('open') && modalTitle.textContent.includes(visitor_id)){
        modal.classList.remove('open'); document.body.style.overflow='';
      }
      await fetchList();
    } catch(e){ console.error(e); alert('فشل الحذف: '+(e.message||e)); }
  }

  deleteAllBtn.addEventListener('click', async ()=>{
    if (!csrf){ await fetchList(); }
    const ok = confirm('تحذير شديد: هذا سيمسح كل الإرسالات من Elementor والاعتمادات وأي جداول submissions. هل تريد المتابعة؟');
    if (!ok) return;
    const confirmText = prompt('للتأكيد اكتب YES (أحرف كبيرة):');
    if (confirmText !== 'YES') return;
    try{
      const form = new FormData();
      form.append('csrf', csrf);
      form.append('confirm', 'YES');
      const res = await fetch('dashboard.php?action=delete_all', {method:'POST', body:form});
      const data = await res.json();
      if (!data.ok) throw new Error(data.error || 'فشل حذف الكل');
      toast('تم حذف كل الإرسالات');
      if (modal.classList.contains('open')){ modal.classList.remove('open'); document.body.style.overflow=''; }
      await fetchList();
    }catch(e){ console.error(e); alert('فشل حذف الكل: '+(e.message||e)); }
  });

  modal.addEventListener('click', (ev)=>{ if(ev.target===modal){ modal.classList.remove('open'); document.body.style.overflow=''; }});
  closeModal.addEventListener('click', ()=>{ modal.classList.remove('open'); document.body.style.overflow=''; });

  manualBtn.addEventListener('click', fetchList);
  fetchList();
  setInterval(fetchList, 5000);

  // فتح تلقائي لو وُجد ?vid=...
  const quick = new URLSearchParams(location.search).get('vid');
  if (quick) (async()=>{
    try{
      const res = await fetch('dashboard.php?action=list&vid='+encodeURIComponent(quick), {headers:{'Accept':'application/json'}});
      const data = await res.json();
      csrf = data.csrf || csrf;
      renderBars(data.items||[], data.sitePages||[]);
      const t = (data.items||[]).find(x=>x.visitor_id===quick);
      if (t) openDetails(t.visitor_id, t.visitor_pages, data.sitePages||[], '');
    }catch(e){ console.error(e); }
  })();
})();
</script>
</body>
</html>
