<?php

namespace OPNsense\Nmap;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->profileForm = $this->getForm('profile');
        $this->view->profileGrid = $this->getFormGrid('profile');
        $this->view->pick('OPNsense/Nmap/index');
    }
}
