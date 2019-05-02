<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Auth extends CI_Controller
{
    public function __construct()
    {
        parent::__construct();
        $this->load->library('form_validation');
    }

    public function index()
    {
        $this->form_validation->set_rules('email', 'Email', 'required|trim|valid_email');
        $this->form_validation->set_rules('password', 'Password', 'required|trim');
        if ($this->form_validation->run()) {
            $this->_login();
        } else {
            $data['title'] = 'User Login';
            $this->load->view('templates/auth_header', $data);
            $this->load->view('auth/login');
            $this->load->view('templates/auth_footer');
        }
    }

    private function _login()
    {
        $email = $this->input->post('email');
        $password = $this->input->post('password');
        $user = $this->db->get_where('user', ['email' => $email])->row_array();
        //jika user ada atau not null
        if ($user) {
            //jika user aktif
            if ($user['is_active'] == 1) {
                //cek password
                if (password_verify($password, $user['password'])) {
                    $data = [
                        'email' => $user['email'],
                        'role_id' => $user['role_id']
                    ];
                    $this->session->set_userdata($data);
                    redirect('user');
                }
                //jika password salah
                else {
                    $this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert">Wrong password!</div>');
                    redirect('auth');
                }
            }
            //jika user belum aktifasi
            else {
                $this->session->set_flashdata('message', '<div class="alert alert-warning" role="alert">Account has not been activated. Please Activated!</div>');
                redirect('auth');
            }
        }
        //jika user tidak ada atau null
        else {
            $this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert">Email is not registered. Please Register!</div>');
            redirect('auth');
        }
    }

    public function registration()
    {
        $this->form_validation->set_rules('name', 'Name', 'required|trim');
        $this->form_validation->set_rules('email', 'Email', 'required|trim|valid_email|is_unique[user.email]', [
            'is_unique' => '%s is already registered!'
        ]);
        $this->form_validation->set_rules('password1', 'Password', 'required|trim|min_length[3]|matches[password2]', [
            'matches' => '%s don\'t match!',
            'min_length' => '%s min 3 characters.',
            'required' => '%s is required!'
        ]);
        $this->form_validation->set_rules('password2', 'Repeat Password', 'required|trim|matches[password1]', [
            'matches' => 'Password don\'t match!',
            'required' => 'Password is required!'
        ]);

        if ($this->form_validation->run()) {
            $data = [
                'name' => htmlspecialchars($this->input->post('name', true)),
                'email' => htmlspecialchars($this->input->post('email', true)),
                'password' => password_hash($this->input->post('password1'), PASSWORD_DEFAULT),
                'image' => 'default.jpg',
                'role_id' => 2,
                'is_active' => 1,
                'date_created' => time()
            ];

            $this->db->insert('user', $data);
            $this->session->set_flashdata('message', '<div class="alert alert-success" role="alert">Account has been created. Please Login!</div>');
            redirect('auth');
        } else {
            //form validation == False
            $data['title'] = 'User Registration';
            $this->load->view('templates/auth_header', $data);
            $this->load->view('auth/registration');
            $this->load->view('templates/auth_footer');
        }
    }

    public function logout()
    {
        $this->session->unset_userdata('email');
        $this->session->unset_userdata('role_id');
        $this->session->set_flashdata('message', '<div class="alert alert-primary" role="alert">Account has been logged out!</div>');
        redirect('auth');
    }
}
