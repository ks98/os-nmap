<?php

namespace OPNsense\Nmap\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

class ProfilesController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'nmap';
    protected static $internalModelClass = 'OPNsense\\Nmap\\Nmap';

    public function searchProfileAction()
    {
        return $this->searchBase('profiles.profile', null, 'name');
    }

    public function getProfileAction($uuid = null)
    {
        return $this->getBase('profile', 'profiles.profile', $uuid);
    }

    public function setProfileAction($uuid)
    {
        return $this->setBase('profile', 'profiles.profile', $uuid);
    }

    public function addProfileAction()
    {
        return $this->addBase('profile', 'profiles.profile');
    }

    public function delProfileAction($uuid)
    {
        return $this->delBase('profiles.profile', $uuid);
    }
}
