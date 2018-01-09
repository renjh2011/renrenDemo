package io.renren.service.oauth;

import io.renren.entity.oauth.Client;

import java.util.List;

/**
 * <p>Date: 14-1-28
 * <p>Version: 1.0
 */
public interface ClientService {

//    public Client createClient(Client client);
//    public Client updateClient(Client client);
//    public void deleteClient(Long clientId);

    Client findOne(Long id);

//    List<Client> findAll();

    Client findByClientId(String clientId);
    Client findByClientSecret(String clientSecret);

}
