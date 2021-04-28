/********************************************************************************/
/* 																				*/
/* Copyright [2016]	Robson de Melo Silva,										*/
/* 					Vitoria Akemi Kanegae,										*/
/* 					Jose Ricardo de Oliveira Damico								*/
/* 																				*/
/* Licensed under the Apache License, Version 2.0 (the "License");				*/
/* you may not use this file except in compliance with the License.				*/
/* You may obtain a copy of the License at										*/
/* 																				*/
/*     http://www.apache.org/licenses/LICENSE-2.0								*/
/* 																				*/
/* Unless required by applicable law or agreed to in writing, software			*/
/* distributed under the License is distributed on an "AS IS" BASIS,			*/
/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.		*/
/* See the License for the specific language governing permissions and			*/
/* limitations under the License.												*/
/*																				*/
/********************************************************************************/

package org.jdamico.csigner.ui;

import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

import org.jdamico.scryptool.commons.Constants;
import org.jdamico.scryptool.commons.TopLevelException;
import org.jdamico.scryptool.commons.Utils;
import org.jdamico.scryptool.crypto.AddVisibleSignature;
import org.jdamico.scryptool.crypto.PKCS11_Helper;

public class SignatureUI extends JFrame implements ActionListener {

	private static final long serialVersionUID = 1L;
	private JLabel labelName = new JLabel("Selecione o Arquivo:");
	private JTextField fileName = new JTextField("Selecione a DLL");
	private JButton buttonSelect = new JButton("Procurar");
	private JFileChooser fileChooser = new JFileChooser();
	private JFileChooser selectDll = new JFileChooser();
	private JButton signButton = new JButton("Assinar");
	private JButton selectLibButton = new JButton("Alterar DLL");
	private String libSource = "";

	public SignatureUI() {

		this.setLayout(null);
		this.setTitle("Assinatura de documentos");
		scaleComponents();
		addComponentes();
		buttonSelect.addActionListener(this);
		signButton.addActionListener(this);
		selectLibButton.addActionListener(this);
		fileName.addActionListener(this);
		this.setVisible(true);
		fileName.setText("Selecione o arquivo a ser assinado.");
	}

	private void scaleComponents() {
		Dimension dim = Toolkit.getDefaultToolkit().getScreenSize();
		int xLocation = (dim.width /2 ) - 300;
		int yLocation = (dim.height /2) - 100 ;
		this.setBounds(xLocation, yLocation, 600, 200);

		this.setResizable(false);
		this.setDefaultCloseOperation(DISPOSE_ON_CLOSE);
		labelName.setBounds(10, 10, 130, 50);
		fileName.setEditable(false);
		signButton.setEnabled(false);
		buttonSelect.setEnabled(true);
		fileName.setBounds(150, 25, 300, 25);
		buttonSelect.setBounds(470, 25, 100, 25);
		signButton.setBounds(250,70, 100, 30);
		selectLibButton.setBounds(480, 135, 100, 25);
		
	}

	private void addComponentes() {
		this.add(labelName);
		this.add(fileName);
		this.add(buttonSelect);
		this.add(signButton);
		
	}


	public void actionPerformed(ActionEvent e) {

		if (e.getSource() == buttonSelect) {
			int returnVal = fileChooser.showOpenDialog(this);
			if (returnVal == JFileChooser.APPROVE_OPTION) {
				selectFile();
			}

		} else if(e.getSource() == signButton){
			if (fileName.getText().isEmpty()){
				JOptionPane.showMessageDialog(null, "Favor inserir o documento!", "Falha", JOptionPane.ERROR_MESSAGE);
			}else{
				signDocumento();
			}
		} 
	}
	private String selectLib(){
		File file = selectDll.getSelectedFile();
		return file.getAbsolutePath();
		
	}

	private void selectFile(){
		File file = fileChooser.getSelectedFile();
		fileName.setText(file.getAbsolutePath());
		signButton.setEnabled(true);
	}

	private void signDocumento(){
		
		String libPath = tryFindLib();
		
		File arquivo = new File(fileName.getText());
		JPasswordField pf = new JPasswordField();
		int opt = JOptionPane.showConfirmDialog(null,pf,"Digite a senha do Token.",JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

		if(opt == JOptionPane.OK_OPTION){
			String senha = new String (pf.getPassword());
			
			
			
			
			if(fileName.getText().endsWith(".pdf")){
			
				try{
					AddVisibleSignature cvs = new AddVisibleSignature(arquivo, libPath, senha.toString());
					//emb.signPDF(arquivo, libPath, senha.toString());
					JOptionPane.showMessageDialog(null, "Documento assinado com sucesso e salvo em : "+arquivo.getParent()+"\\signed\\"+arquivo.getName(), "Sucesso", JOptionPane.INFORMATION_MESSAGE);
				} catch (IOException e) {
					e.printStackTrace();
					JOptionPane.showMessageDialog(null, "Falha ao Executar a Assinatura!", "Falha", JOptionPane.ERROR_MESSAGE);
				} catch (UnrecoverableKeyException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (KeyStoreException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (CertificateException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (TopLevelException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}finally{
					this.dispose();
				}
			}else{
				JOptionPane.showMessageDialog(null, "Para documentos diferentes de PDF as asinaturas são geradas em arquivos separados", "Atenção", JOptionPane.WARNING_MESSAGE);
				PKCS11_Helper pki = new PKCS11_Helper();
				try {
					pki.signSelectedFile(arquivo, libPath, senha.toString());
					JOptionPane.showMessageDialog(null, "Documento assinado com sucesso e salvo em : "+arquivo.getParent()+"\\signed\\"+arquivo.getName()+".signature", "Sucesso", JOptionPane.INFORMATION_MESSAGE);
				} catch (TopLevelException e) {
					JOptionPane.showMessageDialog(null, "Falha ao Executar a Assinatura!", "Falha", JOptionPane.ERROR_MESSAGE);
					e.printStackTrace();
				}
			}
		}
	}

	private String tryFindLib() {
		String libPath = null;
		File libFile = null;
		if(Utils.getInstance().isWindows()) libPath = Constants.WIN_COMMON_LIB;	
		else libPath = Constants.LINUX_COMMON_LIB;	
		libFile = new File(libPath);
		if(!libFile.exists() || !libFile.isFile()) {
			JOptionPane.showMessageDialog(null, "Não encontrei a biblioteca do seu token, por favor selecione-a no seu computador", "Falha", JOptionPane.ERROR_MESSAGE);
			int returnVal = selectDll.showOpenDialog(this);
			if (returnVal == JFileChooser.APPROVE_OPTION) {
				libPath = selectLib();
			}
			System.out.println("libFile: "+libFile);
		}
		return libPath;
	}

	public String getDllSource() {
		return libSource;
	}

	public void setDllSource(String dllSource) {
		this.libSource = dllSource;
	}
	

}
