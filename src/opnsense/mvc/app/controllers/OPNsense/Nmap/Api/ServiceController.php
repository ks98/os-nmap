<?php

namespace OPNsense\Nmap\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Nmap\Nmap;

class ServiceController extends ApiControllerBase
{
    private const RESULTS_PATH = '/var/db/nmap/scan_results.json';
    private const STATUS_PATH = '/var/db/nmap/scan_status.json';
    private const LOOPBACK_HOSTNAMES = array(
        'localhost',
        'localhost.localdomain',
        'ip6-localhost',
        'ip6-loopback',
    );

    private function isValidHostname($hostname)
    {
        if (empty($hostname) || strlen($hostname) > 253) {
            return false;
        }
        if (substr($hostname, -1) === '.') {
            $hostname = substr($hostname, 0, -1);
        }
        $labels = explode('.', $hostname);
        foreach ($labels as $label) {
            if ($label === '' || strlen($label) > 63) {
                return false;
            }
            if ($label[0] === '-' || $label[strlen($label) - 1] === '-') {
                return false;
            }
            if (!preg_match('/^[A-Za-z0-9-]+$/', $label)) {
                return false;
            }
        }
        return true;
    }

    private function isValidTarget($target)
    {
        if (empty($target) || strlen($target) > 255) {
            return false;
        }
        if (preg_match('/\s/', $target)) {
            return false;
        }
        if (strpos($target, '-') === 0) {
            return false;
        }
        if (strpos($target, '/') !== false) {
            $parts = explode('/', $target, 2);
            if (count($parts) !== 2) {
                return false;
            }
            $addr = $parts[0];
            $prefix = $parts[1];
            if (!ctype_digit($prefix)) {
                return false;
            }
            if (filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $prefix = (int)$prefix;
                return $prefix >= 0 && $prefix <= 32;
            }
            if (filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $prefix = (int)$prefix;
                return $prefix >= 0 && $prefix <= 128;
            }
            return false;
        }
        if (filter_var($target, FILTER_VALIDATE_IP)) {
            return true;
        }
        return $this->isValidHostname($target);
    }

    private function isValidTargetsList($targets)
    {
        $list = array_filter(explode(',', $targets));
        if (empty($list)) {
            return false;
        }
        foreach ($list as $target) {
            if (!$this->isValidTarget($target)) {
                return false;
            }
        }
        return true;
    }

    private function isLoopbackAddress($addr)
    {
        if (filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return strpos($addr, '127.') === 0;
        }
        if (filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $packed = inet_pton($addr);
            if ($packed === false) {
                return false;
            }
            return $packed === inet_pton('::1');
        }
        return false;
    }

    private function isLoopbackInterface($ifname, $ifdevice, $descr)
    {
        $ifname = strtolower((string)$ifname);
        $ifdevice = strtolower((string)$ifdevice);
        $descr = strtolower((string)$descr);

        if (preg_match('/^lo[0-9]*$/', $ifname)) {
            return true;
        }
        if ($ifdevice !== '' && preg_match('/^lo[0-9]*$/', $ifdevice)) {
            return true;
        }
        if ($descr === 'loopback' || strpos($descr, 'loopback') !== false) {
            return true;
        }
        return false;
    }

    private function isLoopbackTarget($target)
    {
        $target = trim((string)$target);
        if ($target === '') {
            return false;
        }
        $normalized = strtolower($target);
        if (substr($normalized, -1) === '.') {
            $normalized = substr($normalized, 0, -1);
        }
        if (in_array($normalized, self::LOOPBACK_HOSTNAMES, true)) {
            return true;
        }
        if (strpos($target, '/') !== false) {
            $parts = explode('/', $target, 2);
            $target = $parts[0];
        }
        return $this->isLoopbackAddress($target);
    }

    private function hasLoopbackTargets($targets)
    {
        $list = array_filter(explode(',', (string)$targets));
        foreach ($list as $target) {
            if ($this->isLoopbackTarget($target)) {
                return true;
            }
        }
        return false;
    }

    private function legacyProfiles()
    {
        return array(
            'ping' => array('name' => 'Ping scan', 'args' => '-sn'),
            'fast' => array('name' => 'Fast TCP scan', 'args' => '-F -sS'),
            'regular' => array('name' => 'TCP scan', 'args' => '-sS'),
            'service' => array('name' => 'Service detection', 'args' => '-sS -sV'),
            'full' => array('name' => 'Full TCP scan', 'args' => '-sS -p 1-65535'),
            'aggressive' => array('name' => 'Aggressive scan', 'args' => '-A'),
        );
    }

    private function resolveProfile($profileValue)
    {
        $profileValue = trim((string)$profileValue);
        if ($profileValue === '') {
            return null;
        }

        $model = new Nmap();
        $profiles = $model->getNodeByReference('profiles.profile');
        if ($profiles !== null) {
            foreach ($profiles->iterateItems() as $profile) {
                $attrs = $profile->getAttributes();
                $uuid = isset($attrs['uuid']) ? (string)$attrs['uuid'] : '';
                $name = trim((string)$profile->name);
                if (($uuid !== '' && $uuid === $profileValue) || ($name !== '' && $name === $profileValue)) {
                    $description = trim((string)$profile->description);
                    $label = $name !== '' ? $name : $profileValue;
                    if ($description !== '') {
                        $label .= ' - ' . $description;
                    }
                    if (strlen($label) > 120) {
                        $label = substr($label, 0, 120);
                    }
                    $open_only = ((string)$profile->open_only === '1') ? '1' : '0';
                    $skip_discovery = ((string)$profile->skip_discovery === '1') ? '1' : '0';
                    $no_dns = ((string)$profile->no_dns === '1') ? '1' : '0';
                    $ipv6 = ((string)$profile->ipv6 === '1') ? '1' : '0';
                    return array(
                        'id' => $uuid !== '' ? $uuid : $profileValue,
                        'name' => $label,
                        'args' => trim((string)$profile->args),
                        'open_only' => $open_only,
                        'skip_discovery' => $skip_discovery,
                        'no_dns' => $no_dns,
                        'ipv6' => $ipv6,
                    );
                }
            }
        }

        $legacy = $this->legacyProfiles();
        if (isset($legacy[$profileValue])) {
            return array(
                'id' => $profileValue,
                'name' => $legacy[$profileValue]['name'],
                'args' => $legacy[$profileValue]['args'],
                'open_only' => '0',
                'skip_discovery' => '0',
                'no_dns' => '0',
                'ipv6' => '0',
            );
        }

        return null;
    }

    private function calculateIpv4Network($ip, $cidr)
    {
        $ip_long = ip2long($ip);
        if ($ip_long === false) {
            return null;
        }
        $cidr = (int)$cidr;
        if ($cidr < 0 || $cidr > 32) {
            return null;
        }
        $mask = $cidr === 0 ? 0 : (~((1 << (32 - $cidr)) - 1)) & 0xffffffff;
        $network = long2ip($ip_long & $mask);
        return $network . '/' . $cidr;
    }

    private function netmaskToPrefix($netmask)
    {
        if ($netmask === null || $netmask === '') {
            return null;
        }
        if (ctype_digit((string)$netmask)) {
            $value = (int)$netmask;
            if ($value >= 0 && $value <= 128) {
                return $value;
            }
            return null;
        }
        if (preg_match('/^0x[0-9a-fA-F]+$/', $netmask)) {
            $mask_long = hexdec(substr($netmask, 2));
            $bits = sprintf('%032b', $mask_long & 0xffffffff);
            return substr_count($bits, '1');
        }
        if (!filter_var($netmask, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return null;
        }
        $mask_long = ip2long($netmask);
        if ($mask_long === false) {
            return null;
        }
        $bits = sprintf('%032b', $mask_long & 0xffffffff);
        return substr_count($bits, '1');
    }

    private function extractPrefix($entry, $fallback)
    {
        if (is_array($entry)) {
            foreach (array('prefix', 'prefixlen', 'prefix_len', 'prefix_length', 'subnet', 'cidr', 'masklen') as $key) {
                if (isset($entry[$key]) && $entry[$key] !== '' && ctype_digit((string)$entry[$key])) {
                    return (int)$entry[$key];
                }
            }
            foreach (array('netmask', 'mask') as $key) {
                if (isset($entry[$key]) && $entry[$key] !== '') {
                    $prefix = $this->netmaskToPrefix((string)$entry[$key]);
                    if ($prefix !== null) {
                        return $prefix;
                    }
                }
            }
        }
        if ($fallback !== null && $fallback !== '' && ctype_digit((string)$fallback)) {
            return (int)$fallback;
        }
        return null;
    }

    private function readInterfaceAddresses($ifname, $ifdevice)
    {
        $backend = new Backend();
        $payload = $backend->configdpRun('interface address', array($ifname));
        $data = json_decode($payload, true);
        if (is_array($data)) {
            if (isset($data[$ifname]) && is_array($data[$ifname])) {
                return $data[$ifname];
            }
            if (!empty($ifdevice) && isset($data[$ifdevice]) && is_array($data[$ifdevice])) {
                return $data[$ifdevice];
            }
        }
        if (!empty($ifdevice) && $ifdevice !== $ifname) {
            $payload = $backend->configdpRun('interface address', array($ifdevice));
            $data = json_decode($payload, true);
            if (is_array($data)) {
                if (isset($data[$ifdevice]) && is_array($data[$ifdevice])) {
                    return $data[$ifdevice];
                }
                if (isset($data[$ifname]) && is_array($data[$ifname])) {
                    return $data[$ifname];
                }
            }
        }
        return array();
    }

    private function collectInterfaces()
    {
        $cfg = Config::getInstance()->object();
        $interfaces = array();
        foreach ($cfg->interfaces->children() as $ifname => $node) {
            $descr = isset($node->descr) && (string)$node->descr !== '' ? (string)$node->descr : strtoupper($ifname);
            $ifdevice = isset($node->if) ? (string)$node->if : '';
            if ($this->isLoopbackInterface($ifname, $ifdevice, $descr)) {
                continue;
            }
            $fallback_cidr = isset($node->subnet) && ctype_digit((string)$node->subnet) ? (int)$node->subnet : null;
            $networks = array();
            $addresses = $this->readInterfaceAddresses((string)$ifname, $ifdevice);
            foreach ($addresses as $address) {
                $addr = '';
                if (isset($address['address'])) {
                    $addr = (string)$address['address'];
                } elseif (isset($address['addr'])) {
                    $addr = (string)$address['addr'];
                } elseif (isset($address['ipaddr'])) {
                    $addr = (string)$address['ipaddr'];
                }
                if ($addr === '' || !filter_var($addr, FILTER_VALIDATE_IP)) {
                    if (strpos($addr, '%') !== false) {
                        $addr = explode('%', $addr, 2)[0];
                    }
                    if (strpos($addr, '/') !== false) {
                        $parts = explode('/', $addr, 2);
                        $addr = $parts[0];
                    }
                    if ($addr === '' || !filter_var($addr, FILTER_VALIDATE_IP)) {
                        continue;
                    }
                }
                if ($this->isLoopbackAddress($addr)) {
                    continue;
                }
                $is_ipv6 = filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
                $prefix = $this->extractPrefix($address, $is_ipv6 ? null : $fallback_cidr);
                if ($prefix === null && isset($address['address']) && strpos((string)$address['address'], '/') !== false) {
                    $parts = explode('/', (string)$address['address'], 2);
                    if (isset($parts[1]) && ctype_digit($parts[1])) {
                        $prefix = (int)$parts[1];
                    }
                }
                if ($prefix === null) {
                    continue;
                }
                $network = $addr . '/' . $prefix;
                if (!in_array($network, $networks, true)) {
                    $networks[] = $network;
                    $interfaces[] = array(
                        'id' => (string)$ifname,
                        'name' => $descr,
                        'address' => $addr,
                        'cidr' => (int)$prefix,
                        'network' => $network,
                    );
                }
            }
            if (!empty($networks)) {
                continue;
            }
            $ip = isset($node->ipaddr) ? (string)$node->ipaddr : '';
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || $fallback_cidr === null) {
                continue;
            }
            if ($this->isLoopbackAddress($ip)) {
                continue;
            }
            $network = $this->calculateIpv4Network($ip, $fallback_cidr);
            if ($network === null) {
                continue;
            }
            $interfaces[] = array(
                'id' => (string)$ifname,
                'name' => $descr,
                'address' => $ip,
                'cidr' => (int)$fallback_cidr,
                'network' => $network,
            );
        }
        return $interfaces;
    }

    private function runScan($mode, $targets, $profile, $open_only, $no_dns, $skip_discovery, $ipv6, $custom_args, $background = false)
    {
        $backend = new Backend();
        $custom_b64 = $custom_args === '' ? '' : base64_encode($custom_args);
        $action = $background ? 'nmap scan_background' : 'nmap scan';
        return $backend->configdpRun($action, array(
            $mode,
            $targets,
            $profile,
            $open_only,
            $no_dns,
            $skip_discovery,
            $ipv6,
            $custom_b64,
        ));
    }

    public function interfacesAction()
    {
        return array('interfaces' => $this->collectInterfaces());
    }

    public function resultsAction()
    {
        $data = array(
            'generated_at' => null,
            'hosts' => array(),
        );
        if (is_file(self::RESULTS_PATH)) {
            $raw = file_get_contents(self::RESULTS_PATH);
            $data = json_decode($raw, true);
            if (is_array($data)) {
                if (!empty($data['profile'])) {
                    $resolved = $this->resolveProfile($data['profile']);
                    if ($resolved !== null) {
                        $data['profile'] = $resolved['name'];
                    }
                }
            } else {
                $data = array(
                    'generated_at' => null,
                    'hosts' => array(),
                );
            }
        }
        $status = $this->readScanStatus();
        if ($status !== null) {
            if (!empty($status['profile'])) {
                $resolved = $this->resolveProfile($status['profile']);
                if ($resolved !== null) {
                    $status['profile'] = $resolved['name'];
                }
            }
            $data['scan_status'] = $status;
        }
        return $data;
    }

    public function statusAction()
    {
        $status = $this->readScanStatus();
        if ($status !== null && !empty($status['profile'])) {
            $resolved = $this->resolveProfile($status['profile']);
            if ($resolved !== null) {
                $status['profile'] = $resolved['name'];
            }
        }
        return array('scan_status' => $status);
    }

    public function cancelscanAction()
    {
        if (!$this->request->isPost()) {
            return array("message" => "Unable to cancel scan", "cancelled" => false);
        }

        $pid = trim((string)$this->request->getPost('pid'));
        if ($pid === '' || !ctype_digit($pid)) {
            return array("message" => "Invalid PID", "cancelled" => false);
        }

        $backend = new Backend();
        $output = $backend->configdpRun('nmap cancel', array($pid));
        return array("output" => $output);
    }

    public function clearresultsAction()
    {
        if (!$this->request->isPost()) {
            return array("message" => "Unable to clear scan results", "cleared" => false);
        }

        if (!is_file(self::RESULTS_PATH)) {
            return array("message" => "No scan results to clear", "cleared" => true);
        }

        if (@unlink(self::RESULTS_PATH)) {
            return array("message" => "Scan results cleared", "cleared" => true);
        }

        return array("message" => "Unable to clear scan results", "cleared" => false);
    }

    public function scanAction()
    {
        if (!$this->request->isPost()) {
            return array("message" => "Unable to run scan action");
        }

        $target = trim((string)$this->request->getPost('target'));
        $profileValue = (string)$this->request->getPost('profile');
        $open_only = (string)$this->request->getPost('open_only');
        $no_dns = (string)$this->request->getPost('no_dns');
        $skip_discovery = (string)$this->request->getPost('skip_discovery');
        $ipv6 = (string)$this->request->getPost('ipv6');

        $profile = $this->resolveProfile($profileValue);
        if ($profile === null) {
            return array("message" => "Invalid scan profile");
        }

        if ($open_only === '') {
            $open_only = $profile['open_only'];
        }
        if ($no_dns === '') {
            $no_dns = $profile['no_dns'];
        }
        if ($skip_discovery === '') {
            $skip_discovery = $profile['skip_discovery'];
        }
        if ($ipv6 === '') {
            $ipv6 = $profile['ipv6'];
        }

        foreach (array($open_only, $no_dns, $skip_discovery, $ipv6) as $flag) {
            if (!in_array($flag, array('0', '1'))) {
                return array("message" => "Invalid option value");
            }
        }

        if (!$this->isValidTarget($target)) {
            return array("message" => "Invalid target value");
        }
        if ($this->isLoopbackTarget($target)) {
            return array("message" => "Loopback targets are not allowed");
        }

        $output = $this->runScan(
            'simple',
            $target,
            $profile['id'],
            $open_only,
            $no_dns,
            $skip_discovery,
            $ipv6,
            $profile['args'],
            true
        );
        return array("output" => $output);
    }

    public function scanhostsAction()
    {
        if (!$this->request->isPost()) {
            return array("message" => "Unable to run scan action");
        }

        $targets = trim((string)$this->request->getPost('targets'));
        $profileValue = (string)$this->request->getPost('profile');
        $open_only = (string)$this->request->getPost('open_only');
        $no_dns = (string)$this->request->getPost('no_dns');
        $skip_discovery = (string)$this->request->getPost('skip_discovery');
        $ipv6 = (string)$this->request->getPost('ipv6');

        $profile = $this->resolveProfile($profileValue);
        if ($profile === null) {
            return array("message" => "Invalid scan profile");
        }

        if ($open_only === '') {
            $open_only = $profile['open_only'];
        }
        if ($no_dns === '') {
            $no_dns = $profile['no_dns'];
        }
        if ($skip_discovery === '') {
            $skip_discovery = $profile['skip_discovery'];
        }
        if ($ipv6 === '') {
            $ipv6 = $profile['ipv6'];
        }

        foreach (array($open_only, $no_dns, $skip_discovery, $ipv6) as $flag) {
            if (!in_array($flag, array('0', '1'))) {
                return array("message" => "Invalid option value");
            }
        }

        if (!$this->isValidTargetsList($targets)) {
            return array("message" => "Invalid target list");
        }
        if ($this->hasLoopbackTargets($targets)) {
            return array("message" => "Loopback targets are not allowed");
        }

        $output = $this->runScan(
            'hosts',
            $targets,
            $profile['id'],
            $open_only,
            $no_dns,
            $skip_discovery,
            $ipv6,
            $profile['args'],
            true
        );
        return array("output" => $output);
    }

    private function readScanStatus()
    {
        if (!is_file(self::STATUS_PATH)) {
            return null;
        }
        $raw = file_get_contents(self::STATUS_PATH);
        if ($raw === false) {
            return null;
        }
        $data = json_decode($raw, true);
        return is_array($data) ? $data : null;
    }

    public function scancustomAction()
    {
        if (!$this->request->isPost()) {
            return array("message" => "Unable to run scan action");
        }

        $target = trim((string)$this->request->getPost('target'));
        $custom_args = (string)$this->request->getPost('custom_args');

        if (!$this->isValidTarget($target)) {
            return array("message" => "Invalid target value");
        }
        if ($this->isLoopbackTarget($target)) {
            return array("message" => "Loopback targets are not allowed");
        }

        $output = $this->runScan('custom', $target, 'custom', '0', '0', '0', '0', $custom_args, true);
        return array("output" => $output);
    }
}
