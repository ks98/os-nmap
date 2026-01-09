<?php

namespace OPNsense\Nmap\Migrations;

use OPNsense\Base\BaseModelMigration;

class M1_0_0 extends BaseModelMigration
{
    public function run($model)
    {
        if ($model->getNodeByReference('profiles') === null) {
            $model->addChild('profiles');
        }

        $profiles = $model->getNodeByReference('profiles.profile');
        if ($profiles === null) {
            return;
        }

        foreach ($profiles->iterateItems() as $profile) {
            return;
        }

        $defaults = array(
            array(
                'name' => 'Ping scan',
                'description' => 'Host discovery only (-sn)',
                'args' => '-sn',
                'open_only' => '0',
                'skip_discovery' => '0',
                'no_dns' => '0',
                'ipv6' => '0',
            ),
            array(
                'name' => 'Fast TCP scan',
                'description' => 'Top 100 ports (-F -sS)',
                'args' => '-F -sS',
                'open_only' => '0',
                'skip_discovery' => '0',
                'no_dns' => '0',
                'ipv6' => '0',
            ),
            array(
                'name' => 'TCP scan',
                'description' => 'Top 1000 ports (-sS)',
                'args' => '-sS',
                'open_only' => '0',
                'skip_discovery' => '0',
                'no_dns' => '0',
                'ipv6' => '0',
            ),
            array(
                'name' => 'Service detection',
                'description' => 'Top 1000 ports (-sS -sV)',
                'args' => '-sS -sV',
                'open_only' => '0',
                'skip_discovery' => '0',
                'no_dns' => '0',
                'ipv6' => '0',
            ),
            array(
                'name' => 'Full TCP scan',
                'description' => 'All ports 1-65535 (-sS -p 1-65535)',
                'args' => '-sS -p 1-65535',
                'open_only' => '0',
                'skip_discovery' => '0',
                'no_dns' => '0',
                'ipv6' => '0',
            ),
            array(
                'name' => 'Aggressive scan',
                'description' => 'OS, version, scripts, traceroute (-A)',
                'args' => '-A',
                'open_only' => '0',
                'skip_discovery' => '0',
                'no_dns' => '0',
                'ipv6' => '0',
            ),
        );

        foreach ($defaults as $entry) {
            $node = $profiles->add();
            $node->name = $entry['name'];
            $node->description = $entry['description'];
            $node->args = $entry['args'];
            $node->open_only = $entry['open_only'];
            $node->skip_discovery = $entry['skip_discovery'];
            $node->no_dns = $entry['no_dns'];
            $node->ipv6 = $entry['ipv6'];
        }
    }
}
