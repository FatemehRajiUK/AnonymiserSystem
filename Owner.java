//=============================================================================
// The owner creates its anonymous agent. 
// Then, the owner tags the agent to show that the agent wants to go to first itinerary host. 
// The owner chooses a Mixer and sends an encrypted copy of anonymous agent with the required information for decrypting the agent. 

// Please refer to the following journal article published in IET Information Security Journal for more information:
// F. Raji, B. T. Ladani, Anonymity and Security for Autonomous Mobile Agents, IET Information Security, Special Issue on Multi-Agent and Distributed Information Security, Vol.  4, No. 4, pp. 397 - 410, 2010.
//=============================================================================

/*****************************************************************
JADE - Java Agent DEvelopment Framework is a framework to develop 
multi-agent systems in compliance with the FIPA specifications.
Copyright (C) 2000 CSELT S.p.A. 

GNU Lesser General Public License

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation, 
version 2.1 of the License. 

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the
Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA  02111-1307, USA.
*****************************************************************/

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import jade.core.Agent;
import jade.core.AID;
import jade.core.behaviours.*;
import jade.core.ContainerID;
import jade.domain.JADEAgentManagement.WhereIsAgentAction;
//import jade.domain.AMSService;
//import jade.domain.FIPAAgentManagement.*;
import jade.domain.AMSService;
import jade.domain.FIPAAgentManagement.*;


import jade.lang.acl.*;
import jade.wrapper.AgentController;
import jade.wrapper.ContainerController;
import jade.domain.JADEAgentManagement.CreateAgent;

public class Owner extends Agent 
{
		 static int Sym_Key_Size=128; 
		 static String Sym_alg="AES"; 

		 static int Asym_Key_Size=1024; 
		 static String Asym_alg="RSA"; 

		 static int Agent_length=800; 
		 static String pubkeyfile="PublicKey.key";
		 

		 private  byte[] SymEncrypt(byte[] inpBytes, 
		     SecretKey key, String xform) throws Exception { 
		     Cipher cipher = Cipher.getInstance(xform); 
		     cipher.init(Cipher.ENCRYPT_MODE, key); 
		      
		     return cipher.doFinal(inpBytes); 
		   } 


		   private  byte[] SymDecrypt(byte[] inpBytes,SecretKey key, String xform) throws Exception { 
		     Cipher cipher = Cipher.getInstance(xform); 
		     cipher.init(Cipher.DECRYPT_MODE, key); 
		     return cipher.doFinal(inpBytes); 
		   } 


		   private  byte[] AsymEncrypt(byte[] inpBytes, PublicKey key, String xform) throws Exception { 
		    Cipher cipher = Cipher.getInstance(xform); 
		    cipher.init(Cipher.ENCRYPT_MODE, key); 
		    return cipher.doFinal(inpBytes); 
		  } 


		   private  byte[] AsymDecrypt(byte[] inpBytes,PrivateKey key, String xform) throws Exception{ 
		    Cipher cipher = Cipher.getInstance(xform); 
		    cipher.init(Cipher.DECRYPT_MODE, key); 
		    return cipher.doFinal(inpBytes); 
		  } 


		   private  String padding(String in){
		  while (in.length()<Agent_length){ 
		  in=in.concat("$");
		  } 
		  return in; 
		   }


		   public  int unsignedByteToInt(byte b) {
		 		return (int) b & 0xFF;
		 	}


		   private  byte[] FullPubKeys()throws Exception
		   {
		 	  FileInputStream fis = new FileInputStream(pubkeyfile);
		       ByteArrayOutputStream baos = new ByteArrayOutputStream();
		       int b;
		       try
		       {
		                   while ((b = fis.read()) != -1)
		                   {
		                       baos.write(b);
		                   }
		                   fis.close();
		                   baos.flush();
		                   baos.close();
		       } catch (IOException e) {
		                   e.printStackTrace();
		       }
		       return baos.toByteArray();
		 }


		   private int FindPubKey(byte[] bc,byte[] b)throws Exception
		   {
		 	  byte first = b[0];
		 	  int start =0;
		 	  int end = bc.length;
		 	  byte[] buff=new byte[end];
		 	  int srcEnd = b.length;
		 	  buff=bc;
		 	  for (int i = start; i <= (end - srcEnd); i++) 
		 	  {   if (buff[i] != first) continue;
		 		  int myPos = i+1;
		 		  for (int srcPos = 1; srcPos < srcEnd; ) 
		 		  {  if (buff[myPos++] != (b[srcPos++]))
		 				  break;
		 			  if (srcPos == srcEnd) return i - start; // found it
		 		  }
		 	}
		 	return -1;
		   }


	 private String SetAgentCode(String filename)throws Exception
	  {	     
		 ByteArrayOutputStream baos = new ByteArrayOutputStream();
		 try
	     {
			 FileInputStream fis = new FileInputStream(filename);
			 int b;
	            while ((b = fis.read()) != -1)
	            {
	              baos.write(b);
	            }
	            fis.close();
	            baos.flush();
	            baos.close();     
	      } 
		 catch (IOException e) 
		 {
	            e.printStackTrace();
	     }
	     return(baos.toString());
	  }
	       

   protected void setup() 
	    {
		addBehaviour(new CyclicBehaviour(this) 
		{
		 public void action() {
			doWait(10000);		
			
			ACLMessage msg = new ACLMessage(ACLMessage.INFORM);
			try{
	        Random rand = new Random();
	        int min = 1;
	        int max = 4;
	        int num = rand.nextInt(max-min+1)+min;
			String IDnextmixer="Mixer-"+num;
	       	// Generate a secret key 
	        KeyGenerator kg = KeyGenerator.getInstance(Sym_alg); 
	        kg.init(Sym_Key_Size); 
	        SecretKey key = kg.generateKey(); 
		       
		    Object [] args = new Object[6];
	        args[0] = "Itinerary Host-2";
	        KeyPairGenerator akpg = KeyPairGenerator.getInstance(Asym_alg); 
	        akpg.initialize(Asym_Key_Size); 
	        KeyPair akp = akpg.generateKeyPair(); 
	        PublicKey apubk = akp.getPublic(); 
	        PrivateKey aprvk = akp.getPrivate(); 
	        args[1] = Base64.encode(apubk.getEncoded());
	        //
	        args[2]="null,owner";
	        args[3]="null";
	        args[4]="Save-Retaddr";
	        args[5]=SetAgentCode("code.java");
			String data=args[0].toString().concat("***"+args[1].toString());            
            
            data=data.concat("***"+args[2].toString());
            data=data.concat("***"+args[3].toString());
            data=data.concat("***"+args[4].toString());
            data=data.concat("***"+args[5].toString());
            
			data=padding(data);     
			
		    byte[] dataBytes = data.getBytes(); 
		    byte[] encBytes = SymEncrypt(dataBytes, key, Sym_alg); 	
		      
		    byte[] keybyte =key.getEncoded(); 
		    byte[] ff=FullPubKeys();
		    int k=FindPubKey(ff,IDnextmixer.getBytes());
		    int a=IDnextmixer.length()+1;
		   
		    int i,j,m=0;
		    for(i=k+a,j=0;i<ff.length;++i,++j)
		     	{
		 		if(ff[i]!=10)//"\n"
		 			++m;
		 		else 
		 			break;
		     	}
		   	byte[] ss=new byte[m-1];
		    for(i=k+a,j=0;j<m-1;++i,++j)
		      ss[j]=ff[i];
		    String pk = new String(ss); 
		 	X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(Base64.decode(pk));
		 	KeyFactory kf = KeyFactory.getInstance(Asym_alg);
		 	PublicKey pubk= kf.generatePublic(pkSpec);
		 	long d=System.currentTimeMillis();			
		    byte[] enckey = AsymEncrypt(keybyte, pubk, Asym_alg);
		    System.out.println(System.currentTimeMillis()-d);			
		    int size=encBytes.length+enckey.length;
		    byte[] message=new byte[size];
		    
		    for(i=0;i<encBytes.length;++i)
		    	message[i]=encBytes[i];
		    for(i=encBytes.length,j=0;i<size;++i,++j)
		    	message[i]=enckey[j];
		    msg.setContentObject(message);
			AID ai=new AID( "mixer agent"+num, AID.ISLOCALNAME); 
	       	msg.addReceiver( ai);       
			send(msg);
			System.out.println("Sending anonymous agent to the Ano-Sys, Mixer"+num);
			}
			catch (Exception e) 
			{ 
			System.out.println (e.getMessage()); 
			System.exit(-1); 
			} 
			ACLMessage msg2;
			if((msg2= receive())!=null)
				{
				System.out.println( "In owner " +  msg2.getSender().getLocalName() );
				System.exit(0);
				}			
			else 
				block();
				 }

		});

	}

}
