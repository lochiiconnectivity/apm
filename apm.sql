-- MySQL dump 10.11
--
-- Host: localhost    Database: apm
-- ------------------------------------------------------
-- Server version	5.0.51a-3ubuntu5.4

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `applications`
--

DROP TABLE IF EXISTS `applications`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `applications` (
  `id` int(10) NOT NULL auto_increment,
  `pol_id` int(10) NOT NULL,
  `router` varchar(32) NOT NULL,
  `interface` varchar(64) NOT NULL,
  `direction` enum('in','out') NOT NULL default 'out',
  `needapply` enum('5','4','3','2','1','0') NOT NULL default '0',
  `enabled` enum('1','0') NOT NULL default '1',
  PRIMARY KEY  (`id`),
  UNIQUE KEY `pol_id` (`pol_id`,`router`,`interface`,`direction`),
  CONSTRAINT `applications_ibfk_1` FOREIGN KEY (`pol_id`) REFERENCES `policies` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
SET character_set_client = @saved_cs_client;

--
-- Dumping data for table `applications`
--

LOCK TABLES `applications` WRITE;
/*!40000 ALTER TABLE `applications` DISABLE KEYS */;
/*!40000 ALTER TABLE `applications` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `obj_groups`
--

DROP TABLE IF EXISTS `obj_groups`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `obj_groups` (
  `obj_group_id` int(10) NOT NULL,
  `obj_id` int(10) NOT NULL,
  KEY `obj_group_id` (`obj_group_id`),
  KEY `obj_id` (`obj_id`),
  CONSTRAINT `obj_group_id` FOREIGN KEY (`obj_group_id`) REFERENCES `objects` (`id`),
  CONSTRAINT `obj_id` FOREIGN KEY (`obj_id`) REFERENCES `objects` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
SET character_set_client = @saved_cs_client;

--
-- Dumping data for table `obj_groups`
--

LOCK TABLES `obj_groups` WRITE;
/*!40000 ALTER TABLE `obj_groups` DISABLE KEYS */;
/*!40000 ALTER TABLE `obj_groups` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `obj_scopes`
--

DROP TABLE IF EXISTS `obj_scopes`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `obj_scopes` (
  `id` int(2) NOT NULL auto_increment,
  `scope` varchar(32) NOT NULL,
  PRIMARY KEY  (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
SET character_set_client = @saved_cs_client;

--
-- Dumping data for table `obj_scopes`
--

LOCK TABLES `obj_scopes` WRITE;
/*!40000 ALTER TABLE `obj_scopes` DISABLE KEYS */;
INSERT INTO `obj_scopes` VALUES ('1','global');
/*!40000 ALTER TABLE `obj_scopes` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `obj_types`
--

DROP TABLE IF EXISTS `obj_types`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `obj_types` (
  `id` int(2) NOT NULL auto_increment,
  `type` varchar(32) NOT NULL,
  PRIMARY KEY  (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=latin1;
SET character_set_client = @saved_cs_client;

--
-- Dumping data for table `obj_types`
--

LOCK TABLES `obj_types` WRITE;
/*!40000 ALTER TABLE `obj_types` DISABLE KEYS */;
INSERT INTO `obj_types` VALUES (1,'OBJ_GROUP'),(2,'IPV4_ADDR'),(3,'IPV6_ADDR'),(4,'IP_PROTO'),(5,'TCP_PORT'),(6,'UDP_PORT'),(7,'ICMP_TYPECODE');
/*!40000 ALTER TABLE `obj_types` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `objects`
--

DROP TABLE IF EXISTS `objects`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `objects` (
  `id` int(10) NOT NULL auto_increment,
  `type` int(2) NOT NULL,
  `obj_group_type` int(2) default NULL,
  `scope` int(2) NOT NULL,
  `name` varchar(32) NOT NULL,
  `value` varchar(32) NOT NULL,
  `enabled` enum('1','0') NOT NULL default '1',
  PRIMARY KEY  (`id`),
  UNIQUE KEY `scopenametype` (`scope`,`name`,`type`),
  UNIQUE KEY `scopenameobjtype` (`scope`,`name`,`obj_group_type`),
  KEY `type` (`type`),
  KEY `obj_group_type` (`obj_group_type`),
  KEY `scope` (`scope`),
  CONSTRAINT `obj_group_type` FOREIGN KEY (`obj_group_type`) REFERENCES `obj_types` (`id`),
  CONSTRAINT `type` FOREIGN KEY (`type`) REFERENCES `obj_types` (`id`),
  CONSTRAINT `scope` FOREIGN KEY (`scope`) REFERENCES `obj_scopes` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=latin1;
SET character_set_client = @saved_cs_client;

--
-- Dumping data for table `objects`
--

LOCK TABLES `objects` WRITE;
/*!40000 ALTER TABLE `objects` DISABLE KEYS */;
INSERT INTO `objects` VALUES (3,4,0,1,'ICMP','1','1'),(4,4,0,1,'TCP','6','1'),(5,4,0,1,'UDP','17','1'),(6,5,0,1,'TCP-REPLY','gt 1024','1'),(7,5,0,1,'echo-reply','999999999','1');
/*!40000 ALTER TABLE `objects` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `policies`
--

DROP TABLE IF EXISTS `policies`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `policies` (
  `id` int(10) NOT NULL auto_increment,
  `type` varchar(32) NOT NULL,
  `name` varchar(32) NOT NULL,
  `enabled` enum('1','0') NOT NULL default '1',
  PRIMARY KEY  (`id`),
  UNIQUE KEY `nametype` (`name`,`type`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
SET character_set_client = @saved_cs_client;

--
-- Dumping data for table `policies`
--

LOCK TABLES `policies` WRITE;
/*!40000 ALTER TABLE `policies` DISABLE KEYS */;
/*!40000 ALTER TABLE `policies` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `policy_rules`
--

DROP TABLE IF EXISTS `policy_rules`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `policy_rules` (
  `id` int(20) NOT NULL auto_increment,
  `pol_id` int(10) NOT NULL,
  `pol_seq` int(10) NOT NULL,
  `action` enum('permit','deny') NOT NULL default 'deny',
  `proto_obj` int(10) default NULL,
  `s_ip_obj` int(10) default NULL,
  `s_port_obj` int(10) default NULL,
  `d_ip_obj` int(10) default NULL,
  `d_port_obj` int(10) default NULL,
  `flags` varchar(10) default NULL,
  `annotation` text,
  `enabled` enum('1','0') NOT NULL default '1',
  PRIMARY KEY  (`id`),
  UNIQUE KEY `unique_rule` (`pol_id`,`proto_obj`,`s_ip_obj`,`s_port_obj`,`d_ip_obj`,`d_port_obj`,`flags`),
  KEY `pol_id` (`pol_id`),
  KEY `pol_seq` (`pol_seq`),
  KEY `policy_rules_proto_obj` (`proto_obj`),
  KEY `policy_rules_s_port_obj` (`s_port_obj`),
  KEY `policy_rules_d_port_obj` (`d_port_obj`),
  KEY `policy_rules_s_ip_obj` (`s_ip_obj`),
  KEY `policy_rules_d_ip_obj` (`d_ip_obj`),
  CONSTRAINT `policy_rules_pol_id` FOREIGN KEY (`pol_id`) REFERENCES `policies` (`id`),
  CONSTRAINT `policy_rules_proto_obj` FOREIGN KEY (`proto_obj`) REFERENCES `objects` (`id`),
  CONSTRAINT `policy_rules_s_ip_obj` FOREIGN KEY (`s_ip_obj`) REFERENCES `objects` (`id`),
  CONSTRAINT `policy_rules_d_ip_obj` FOREIGN KEY (`d_ip_obj`) REFERENCES `objects` (`id`),
  CONSTRAINT `policy_rules_s_port_obj` FOREIGN KEY (`s_port_obj`) REFERENCES `objects` (`id`),
  CONSTRAINT `policy_rules_d_port_obj` FOREIGN KEY (`d_port_obj`) REFERENCES `objects` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
SET character_set_client = @saved_cs_client;

--
-- Dumping data for table `policy_rules`
--

LOCK TABLES `policy_rules` WRITE;
/*!40000 ALTER TABLE `policy_rules` DISABLE KEYS */;
/*!40000 ALTER TABLE `policy_rules` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `transactions`
--

DROP TABLE IF EXISTS `transactions`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `transactions` (
  `id` bigint(20) NOT NULL auto_increment,
  `timestamp` timestamp NOT NULL default CURRENT_TIMESTAMP on update CURRENT_TIMESTAMP,
  `username` varchar(30) NOT NULL default '',
  `data` text NOT NULL,
  PRIMARY KEY  (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
SET character_set_client = @saved_cs_client;

--
-- Dumping data for table `transactions`
--

LOCK TABLES `transactions` WRITE;
/*!40000 ALTER TABLE `transactions` DISABLE KEYS */;
/*!40000 ALTER TABLE `transactions` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2009-09-09 23:35:18
