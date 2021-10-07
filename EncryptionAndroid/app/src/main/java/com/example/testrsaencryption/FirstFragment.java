package com.example.testrsaencryption;

import android.os.Bundle;
import android.os.Handler;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;

import com.example.testrsaencryption.databinding.FragmentFirstBinding;

public class FirstFragment extends Fragment implements IInstallerWorkerListener {

    private FragmentFirstBinding binding;
    InstallerWorker m_worker = null;
    private Handler m_handler = null;

    @Override
    public View onCreateView(
            LayoutInflater inflater, ViewGroup container,
            Bundle savedInstanceState
    ) {

        m_handler = new Handler();
        m_worker = new InstallerWorker(this, m_handler, ".tmp");
        binding = FragmentFirstBinding.inflate(inflater, container, false);
        return binding.getRoot();
    }

    public void onViewCreated(@NonNull View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        binding.mButtonRun.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Log.i("AES_ENC","Click Run");

                if(m_worker == null){
                    return;
                }
                m_worker.reset();

                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        Log.i("AES_ENC","Do Run");
                        while (m_worker != null && !m_worker.isComplete()){
                            try {
                                Thread.sleep(100);
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }
                            m_worker.handle();
                        }

                        Log.i("AES_ENC","Complete install");
                    }
                }).start();
            }
        });

        binding.mButtonCancel.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if(m_worker != null && !m_worker.isComplete()){
                    m_worker.cancel();
                }
            }
        });

        Utils.checkExternalMedia();

    }


    @Override
    public void onDestroyView() {
        super.onDestroyView();
        binding = null;
    }

    @Override
    public void writeInfo(String string) {
        binding.mOutputText.append(string);
        binding.mOutputText.append("\n");
    }
}