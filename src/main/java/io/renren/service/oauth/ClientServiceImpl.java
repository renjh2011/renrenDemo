package io.renren.service.oauth;

import io.renren.dao.oauth.ClientDao;
import io.renren.entity.oauth.Client;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * <p>Date: 14-2-17
 * <p>Version: 1.0
 */
@Transactional
@Service("ClientService")
public class ClientServiceImpl implements ClientService {
    @Autowired
    private ClientDao clientDao;

    /*@Override
    public Client createClient(Client client) {

        client.setClientId(UUID.randomUUID().toString());
        client.setClientSecret(UUID.randomUUID().toString());
        return clientDao.createClient(client);
    }

    @Override
    public Client updateClient(Client client) {
        return clientDao.updateClient(client);
    }

    @Override
    public void deleteClient(Long clientId) {
        clientDao.deleteClient(clientId);
    }*/

    @Override
    public Client findOne(Long id) {
        return clientDao.findOne(id);
    }

//    @Override
//    public List<Client> findAll() {
//        return clientDao.findAll();
//    }

    @Override
    public Client findByClientId(String clientId) {
        return clientDao.findByClientId(clientId);
    }

    @Override
    public Client findByClientSecret(String clientSecret) {
        return clientDao.findByClientSecret(clientSecret);
    }
}
