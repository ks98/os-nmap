<?php

namespace OPNsense\Nmap\Migrations;

use OPNsense\Base\BaseModelMigration;

class M1_0_1 extends BaseModelMigration
{
    public function run($model)
    {
        $profiles = $model->getNodeByReference('profiles.profile');
        if ($profiles === null) {
            return;
        }

        $fields = array('open_only', 'skip_discovery', 'no_dns', 'ipv6');
        foreach ($profiles->iterateItems() as $profile) {
            foreach ($fields as $field) {
                if (!isset($profile->$field) || (string)$profile->$field === '') {
                    $profile->$field = '0';
                }
            }
        }
    }
}
