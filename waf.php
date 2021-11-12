<?php
ini_set("display_errors", "Off");
ini_set('memory_limit', '-1');
function ehXSS($string) {
    $parametrosxss = array("<SCRIPT", "?sql", "<script", "<script>", "SET", "<iframe", ".css", ".js", "<meta", ">", "?sql=UPDATE", "UPDATE", "*", "**", ",'", "''", "'", "<frame", "<img", "<embed", "<xml", "ALERT(", "<IFRAME", "</", "<?php", "?>", "SCRIPT>", "JS>", "<JS", "JSON>", ".replace", "unescape", "<JSON", "SCRIPT", "DIV", ".CCS", ".JS", "<META", "<FRAME", "<EMBED", "<XML", "<IFRAME", "<IMG", ";--", "nc", "ncat", "netcat", "curl", "telnet", "sudo", ".sh", "install", "sudo", "bash");
    foreach ($parametrosxss as $parametrosxss) {
        if (strpos($string, $parametrosxss) !== false) {
            return true;
        }
    }
}
function flw_xss($input_str) {
    $retornarstring = str_replace(array('<', '>', "'", '"', ')', '('), array('&lt;', '&gt;', '&apos;', '&#x22;', '&#x29;', '&#x28;'), $retornarstring);
    $retornarstring = str_ireplace('%3Cscript', '', $retornarstring);
    return $retornarstring;
}
function flw_xss2($data) {
    // ok
    ;
    $data = str_replace(array('&amp;', '&lt;', '&gt;'), array('&amp;amp;', '&amp;lt;', '&amp;gt;'), $data);
    $data = preg_replace('/(&#*\w+)[- ]+;/u', '$1;', $data);
    $data = preg_replace('/(&#x*[0-9A-F]+);*/iu', '$1;', $data);
    $data = html_entity_decode($data, ENT_COMPAT, 'UTF-8');
    // removendo atributos que comecem com on ou xmlns
    $data = preg_replace('#(<[^>]+?[- "\'])(?:on|xmlns)[^>]*+>#iu', '$1>', $data);
    // removendo os protolocos de vbscript e javascript
    $data = preg_replace('#([a-z]*)[- ]*=[- ]*([`\'"]*)[- ]*j[- ]*a[- ]*v[- ]*a[- ]*s[- ]*c[- ]*r[- ]*i[- ]*p[- ]*t[- ]*:#iu', '$1=$2nojavascript...', $data);
    $data = preg_replace('#([a-z]*)[- ]*=([\'"]*)[- ]*v[- ]*b[- ]*s[- ]*c[- ]*r[- ]*i[- ]*p[- ]*t[- ]*:#iu', '$1=$2novbscript...', $data);
    $data = preg_replace('#([a-z]*)[- ]*=([\'"]*)[- ]*-moz-binding[- ]*:#u', '$1=$2nomozbinding...', $data);
    // so funfa no explorer esse: <span style="width: expression(alert('Ping!'));"></span>
    $data = preg_replace('#(<[^>]+?)style[- ]*=[- ]*[`\'"]*.*?expression[- ]*\([^>]*+>#i', '$1>', $data);
    $data = preg_replace('#(<[^>]+?)style[- ]*=[- ]*[`\'"]*.*?behaviour[- ]*\([^>]*+>#i', '$1>', $data);
    $data = preg_replace('#(<[^>
    ]+?)style[- ]*=[- ]*[`\'"]*.*?s[- ]*c[- ]*r[- ]*i[- ]*p[- ]*t[- ]*:*[^>]*+>#iu', '$1>', $data);
    // removendo algusns elementos nao necessários
    $data = preg_replace('#</*\w+:\w[^>]*+>#i', '', $data);
    do {
        // tags inuteis
        $data_antiga = $data;
        $data = preg_replace('#
            </*(?:applet|b(?:ase|gsound|link)|embed|frame(?:set)?|i(?:frame|layer)|l(?:ayer|ink)|meta|object|s(?:cript|tyle)|title|xml)[^>
        ]*+>#i', '', $data);
    } while ($data_antiga !== $data);
    // cabo
    return $data;
}
?>