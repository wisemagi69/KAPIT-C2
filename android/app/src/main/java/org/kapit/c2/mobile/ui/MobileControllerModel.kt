package org.kapit.c2.mobile.ui

import androidx.lifecycle.ViewModel

/** Memory only. Reuse one repository across rotation; never add a SavedStateHandle here. */
class MobileControllerModel(val controller: MobileController) : ViewModel() {
    override fun onCleared() { controller.close() }
}
