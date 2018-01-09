package io.renren.dao.oauth;

import io.renren.dao.BaseDao;
import io.renren.entity.oauth.Client;

import java.util.List;

/**
 * <p>User: Zhang Kaitao
 * <p>Date: 14-1-28
 * <p>Version: 1.0
 */
public interface ClientDao  extends BaseDao<Client> {

//    public Client createClient(Client client);
//    public Client updateClient(Client client);
//    public void deleteClient(Long clientId);

    Client findOne(Long id);

//    List<Client> findAll();

    Client findByClientId(String clientId);
    Client findByClientSecret(String clientSecret);

}
